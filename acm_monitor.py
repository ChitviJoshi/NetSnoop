#!/usr/bin/env python3
"""
Enhanced System Monitor with Dashboard Integration
Low-level process, memory, and anomaly detection system
"""

import os
import time
import threading
import csv
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

# Configuration
MEMORY_THRESHOLD_MB = 50
CPU_THRESHOLD_PERCENT = 80
PROCESS_BURST_THRESHOLD = 8
PROCESS_BURST_WINDOW = 5  # seconds
ANOMALY_GROUP_WINDOW = 3  # seconds
CSV_FILE = "anomalies.csv"
LOG_FILE = "netsnoop_persistent.txt"
DEBUG_MODE = False  # Set to False to only show anomalies
LOG_PROCESS_TREE = True  # Set to True to log process trees to file
CPU_HIGH_THRESHOLD = 80      # High CPU warning
CPU_CRITICAL_THRESHOLD = 95  # Critical CPU alert
CPU_EXTREME_THRESHOLD = 98   # Extreme CPU alert
MEMORY_HIGH_THRESHOLD = 50    # High memory warning (MB)
MEMORY_CRITICAL_THRESHOLD = 100  # Critical memory alert (MB)
MEMORY_EXTREME_THRESHOLD = 200   # Extreme memory alert (MB)

# Colors for terminal output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"
SEVERITY_COLORS = {
    "HIGH": YELLOW,
    "CRITICAL": RED,
    "EXTREME": MAGENTA
}
SEVERITY_EMOJIS = {
    "HIGH": "🔺",
    "CRITICAL": "🧨", 
    "EXTREME": "💥"
}

SEVERITY_NAMES = {
    "HIGH": "HIGH CPU",
    "CRITICAL": "CRITICAL CPU", 
    "EXTREME": "EXTREME CPU"
}

# Safe parent processes (system processes that can spawn many children)
SAFE_PARENT_NAMES = {
    "systemd", "init", "kthreadd", "ksoftirqd", "rcu_gp", "rcu_par_gp",
    "migration", "watchdog", "systemd-journal", "systemd-udevd",
    "systemd-resolve", "systemd-timesyn", "systemd-logind", "cron",
    "dbus", "NetworkManager", "ssh", "sshd", "kernel", "chrome",
    "firefox", "gnome", "kde"
}

# Global variables for tracking
recent_processes = deque(maxlen=100)
memory_alert_counts = defaultdict(int)
cpu_alert_counts = defaultdict(int)
anomaly_buffer = []
anomaly_counts = {"PROCESS_BURST": 0, "HIGH_MEMORY": 0, "HIGH_CPU": 0, "SUSPICIOUS_PROCESS": 0}
burst_alert_history = {}  # Track recent burst alerts to avoid spam
BURST_COOLDOWN = 30  # seconds before alerting again for same process
previous_cpu_measurements = {}

def get_ist_timestamp():
    """Get current timestamp in IST format (fixed deprecation warning)"""
    utc_now = datetime.now(timezone.utc)
    ist_now = utc_now + timedelta(hours=5, minutes=30)
    return ist_now.strftime("%H:%M:%S")

def get_ist_datetime():
    """Get current datetime in IST format (fixed deprecation warning)"""
    utc_now = datetime.now(timezone.utc)
    ist_now = utc_now + timedelta(hours=5, minutes=30)
    return ist_now.strftime("%Y-%m-%d %H:%M:%S IST")


class AnomalyLogger:
    def __init__(self, csv_file):
        self.csv_file = csv_file
        self.fieldnames = ['timestamp', 'process_name', 'pid', 'reason', 'severity', 'user', 'command']
        self._ensure_csv_exists()

    def _ensure_csv_exists(self):
        """Ensure CSV file exists with proper headers"""
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                writer.writeheader()

    def log_anomaly(self, process_name, reason, pid=None, severity="MEDIUM", user=None, command=None):
        """Log anomaly to CSV file with IST timestamp"""
        try:
            with open(self.csv_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                writer.writerow({
                    'timestamp': get_ist_datetime(),
                    'process_name': process_name,
                    'pid': pid or "",
                    'reason': reason,
                    'severity': severity,
                    'user': user or "",
                    'command': command or ""
                })
        except Exception as e:
            print(f"{RED}❌ Error logging anomaly: {e}{RESET}")
            


def log_message(message, level="INFO"):
    """Log message to persistent log file"""
    try:
        timestamp = get_ist_datetime()
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"{RED}❌ Log write error: {e}{RESET}")

def log_anomaly(process_name, reason, pid=None, severity="MEDIUM", user=None, command=None):
    """Global anomaly logging function"""
    global anomaly_logger
    try:
        anomaly_logger.log_anomaly(process_name, reason, pid, severity, user, command)
        log_message(f"🚨 ANOMALY: {process_name} (PID {pid}) - {reason}")
        
        # Update counters
        if "burst" in reason.lower():
            anomaly_counts["PROCESS_BURST"] += 1
        elif "memory" in reason.lower():
            anomaly_counts["HIGH_MEMORY"] += 1
        elif "cpu" in reason.lower():
            anomaly_counts["HIGH_CPU"] += 1
        else:
            anomaly_counts["SUSPICIOUS_PROCESS"] += 1
            
    except Exception as e:
        print(f"{RED}❌ Anomaly logging error: {e}{RESET}")

def get_name_ppid_uid(pid):
    """Get process name, parent PID, and user ID"""
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            fields = f.read().split()
            name = fields[1].strip("()")
            ppid = int(fields[3])
        
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    break
            else:
                uid = 0
        
        return name, ppid, uid
    except:
        return None, None, None

def get_username(uid):
    """Get username from UID"""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except:
        return str(uid)

def get_cmdline(pid):
    """Get command line for process"""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            args = f.read().replace(b'\x00', b' ').decode().strip()
            return args or "N/A"
    except:
        return "N/A"

def extract_script_name_improved(cmd):
    """Extract script name from command line - improved version"""
    if not cmd or cmd == "N/A":
        return None
    
    parts = cmd.split()
    if not parts:
        return None
    
    # Common script extensions
    script_extensions = [
        '.py', '.sh', '.js', '.pl', '.rb', '.php', '.go', '.rs', '.java', '.cpp', '.c', '.cc', '.cxx',
        '.h', '.hpp', '.hxx', '.swift', '.kt', '.scala', '.lua', '.r', '.R', '.m', '.mm', '.sql',
        '.html', '.css', '.xml', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
        '.bat', '.cmd', '.ps1', '.vbs', '.awk', '.sed', '.perl', '.tcl', '.ex', '.exs', '.clj',
        '.dart', '.tsx', '.jsx', '.vue', '.svelte', '.ts', '.coffee', '.elm', '.hs', '.ml',
        '.f90', '.f95', '.for', '.pas', '.ada', '.vhd', '.v', '.sv', '.asm', '.s'
    ]
    
    # Skip interpreters and look for actual script files
    interpreters = {'python', 'python3', 'node', 'bash', 'sh', 'perl', 'ruby', 'java', 'php', 'go'}
    
    # First pass: Look for files with script extensions
    for i, part in enumerate(parts):
        # Skip flags/options
        if part.startswith('-'):
            continue
            
        # Check if this part has a script extension
        if any(part.lower().endswith(ext) for ext in script_extensions):
            # Extract just the filename
            filename = part.split('/')[-1]
            if filename:
                return filename
    
    # Second pass: Look for non-system paths that might be scripts
    for i, part in enumerate(parts):
        if part.startswith('-'):
            continue
            
        # Skip the interpreter itself
        base_part = part.split('/')[-1]
        if base_part.lower() in interpreters:
            continue
            
        # Skip system directories
        if part.startswith(('/usr/bin/', '/bin/', '/sbin/', '/usr/sbin/', '/usr/lib/')):
            continue
            
        # If it's a path, extract the filename
        if '/' in part:
            filename = part.split('/')[-1]
            # Make sure it's not an interpreter
            if filename and filename.lower() not in interpreters and not filename.startswith('-'):
                return filename
        # If it's just a filename/command and not an interpreter
        elif part and part.lower() not in interpreters and not part.startswith('-'):
            return part
    
    # Third pass: Look for anything that looks like a script after interpreters
    for i, part in enumerate(parts):
        if i == 0:  # Skip the first part (usually the interpreter)
            continue
            
        if part.startswith('-'):
            continue
            
        # This might be a script name
        if part and not part.startswith('/usr/') and not part.startswith('/bin/'):
            filename = part.split('/')[-1] if '/' in part else part
            if filename and filename.lower() not in interpreters:
                return filename
    
    return None
def get_better_process_name(pid, process_name, cmd):
    """Get the best display name for a process with context"""
    if not cmd or cmd == "N/A":
        return process_name.strip("()") if process_name else "unknown"
    
    # First try to extract script name from command
    script_name = extract_script_name_improved(cmd)
    if script_name:
        return script_name
    
    # For system commands, show the command with context
    parts = cmd.split()
    if parts:
        main_cmd = parts[0].split('/')[-1]  # Get command name without path
        
        # If it's a simple system command, show it with some context
        if main_cmd in ['sleep', 'cat', 'echo', 'grep', 'awk', 'sed', 'curl', 'wget']:
            if len(parts) > 1:
                # Show command with first argument
                return f"{main_cmd} {parts[1]}"
            else:
                return main_cmd
        
        # For other commands, try to find the most meaningful part
        return main_cmd
    
    # Fall back to process name, but clean it up
    if process_name:
        clean_name = process_name.strip("()")
        if clean_name:
            return clean_name
    
    return "unknown"
def get_parent_process_info(ppid):
    """Get information about the parent process"""
    try:
        parent_name, parent_ppid, parent_uid = get_name_ppid_uid(ppid)
        if parent_name:
            parent_cmd = get_cmdline(ppid)
            parent_user = get_username(parent_uid) if parent_uid is not None else "unknown"
            return {
                'name': parent_name,
                'cmd': parent_cmd,
                'user': parent_user,
                'ppid': parent_ppid
            }
    except:
        pass
    return None

def get_memory_usage_mb(pid):
    """Get memory usage in MB"""
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    kb = int(line.split()[1])
                    return kb / 1024  # Convert to MB
        return None
    except:
        return None

def get_cpu_usage_simple(pid):
    """Very simple CPU usage detection"""
    try:
        # Read current CPU times
        with open(f"/proc/{pid}/stat", "r") as f:
            fields = f.read().split()
            utime1 = int(fields[13])
            stime1 = int(fields[14])
        
        # Short delay
        time.sleep(0.5)  # 500ms delay
        
        # Read again
        with open(f"/proc/{pid}/stat", "r") as f:
            fields = f.read().split()
            utime2 = int(fields[13])
            stime2 = int(fields[14])
        
        # Calculate difference
        time_diff = (utime2 - utime1) + (stime2 - stime1)
        
        # Convert to percentage (rough approximation)
        # If the process used significant CPU in 0.5 seconds, it's high CPU
        if time_diff > 40:  # Threshold for high CPU
            return 90.0  # Return high value to trigger alert
        elif time_diff > 20:
            return 85.0
        elif time_diff > 5:
            return 70.0
        else:
            return max(time_diff * 2, 0)  # Scale smaller values
            
    except:
        return None

def trace_to_real_instigator(pid):
    """Trace back to find the real instigator process"""
    try:
        cmd = get_cmdline(pid)
        
        # For shell processes, try to get the actual command
        if any(shell in cmd for shell in ["/bin/sh", "/bin/bash", "/bin/dash"]):
            # Look for -c option which contains the actual command
            if " -c " in cmd:
                actual_cmd = cmd.split(" -c ", 1)[1].strip("'\"")
                return actual_cmd
        
        return cmd
    except:
        return None
    
def log_process_with_parent_info(pid, name, user, cmd):
    """Log process with parent information for better context"""
    try:
        # Get parent process info for this PID
        current_name, current_ppid, current_uid = get_name_ppid_uid(pid)
        if current_ppid and current_ppid != 1:  # Don't show init as parent
            parent_name, parent_ppid, parent_uid = get_name_ppid_uid(current_ppid)
            if parent_name:
                parent_cmd = get_cmdline(current_ppid)
                parent_user = get_username(parent_uid) if parent_uid is not None else "unknown"
                
                # Log with parent context
                log_message(f"🌳 PROCESS TREE:")
                log_message(f"    Parent: {parent_name} (PID {current_ppid}, User: {parent_user})")
                log_message(f"    └── Child: {name} (PID {pid}, User: {user})")
                log_message(f"        ├── Executable: {cmd.split()[0] if cmd != 'N/A' else 'N/A'}")
                log_message(f"        └── Command: {cmd}")
                if parent_cmd != 'N/A':
                    log_message(f"    Parent Command: {parent_cmd}")
            else:
                # Fallback to simple logging
                log_message(f"🔧 NEW PROCESS: {name} (PID {pid}, User: {user})")
                log_message(f"    └── Command: {cmd}")
        else:
            # Process has no meaningful parent (or is init child)
            log_message(f"🔧 NEW PROCESS: {name} (PID {pid}, User: {user})")
            log_message(f"    └── Command: {cmd}")
    except Exception as e:
        # Fallback logging in case of errors
        log_message(f"🔧 NEW PROCESS: {name} (PID {pid}, User: {user}) - {cmd}")
        if DEBUG_MODE:
            log_message(f"    Error getting parent info: {e}")

def print_process_tree(pid, name, user, cmd, indent=0):
    """Print process in tree format and log to file"""
    timestamp = get_ist_timestamp()
    indent_str = "    " * indent
    tree_connector = "└── " if indent > 0 else ""
    
    # Print to console only in debug mode
    if DEBUG_MODE:
        print(f"{CYAN}[{timestamp}] 🔧 New Process Detected:{RESET}")
        print(f"{indent_str}{tree_connector}{YELLOW}{name}{RESET} {MAGENTA}(PID {pid}, User: {user}){RESET}")
        print(f"{indent_str}    ├── Executable: {cmd.split()[0] if cmd != 'N/A' else 'N/A'}")
        print(f"{indent_str}    └── CmdLine: {cmd}")
    
    # Log process tree to file if enabled
    if LOG_PROCESS_TREE:
        log_process_with_parent_info(pid, name, user, cmd)

def monitor_memory_usage_of_processes():
    """Monitor memory usage of all processes with severity levels"""
    global memory_alert_counts
    
    while True:
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                if int(pid) == os.getpid():  # Skip your own monitoring script
                    continue

                mem = get_memory_usage_mb(pid)

                # Check different severity levels for memory
                severity = None
                if mem and mem >= MEMORY_EXTREME_THRESHOLD:
                    severity = "EXTREME"
                elif mem and mem >= MEMORY_CRITICAL_THRESHOLD:
                    severity = "CRITICAL"
                elif mem and mem >= MEMORY_HIGH_THRESHOLD:
                    severity = "HIGH"

                if severity:
                    try:
                        with open(f"/proc/{pid}/cmdline", "r") as f:
                            cmd = f.read().replace('\x00', ' ').strip()

                        # Skip monitoring system processes
                        monitoring_keywords = [
                            "acm_monitor.py", "acm.py", "streamlit", "dashboard.py",
                            "monitor_env/bin/streamlit", "monitor_env/bin/python",
                            "/streamlit", "streamlit run"
                        ]
                        
                        if any(keyword in cmd for keyword in monitoring_keywords):
                            continue

                        name, ppid, uid = get_name_ppid_uid(pid)
                        user = get_username(uid) if uid is not None else "unknown"

                        # Extract script name for better display
                        script_name = extract_script_name_improved(cmd)
                        display_name = script_name if script_name else (name or "unknown")

                        memory_alert_counts[pid] += 1
                        count = memory_alert_counts[pid]
                        
                        # Get severity-specific formatting
                        color = SEVERITY_COLORS[severity]
                        emoji = "🧠" if severity == "HIGH" else "🔥" if severity == "CRITICAL" else "💀"
                        severity_name = f"{severity} MEMORY"
                        
                        timestamp = get_ist_datetime()
                        
                        # Enhanced memory alert message
                        alert_msg = f"{CYAN}[{timestamp}] {color}{emoji} {severity_name} Process ({display_name}) PID {pid} x{count}: {mem:.2f} MB → {cmd}{RESET}"
                        
                        print(alert_msg)
                        
                        # Add special handling for critical and extreme cases
                        if severity == "CRITICAL":
                            print(f"{RED}  ⚠️  CRITICAL: Process using {mem:.2f} MB memory - monitor closely{RESET}")
                        elif severity == "EXTREME":
                            print(f"{MAGENTA}  🚨 EXTREME: Process using {mem:.2f} MB memory - potential memory leak!{RESET}")
                        
                        # Log to anomaly system
                        log_anomaly(
                            process_name=display_name,
                            reason=f"{severity_name}: {mem:.2f} MB memory usage",
                            pid=pid,
                            severity=severity,
                            user=user,
                            command=cmd
                        )

                    except (FileNotFoundError, PermissionError):
                        continue
                    except Exception as e:
                        if DEBUG_MODE:
                            print(f"{RED}❌ Memory monitoring error for PID {pid}: {e}{RESET}")

            time.sleep(10)  # Check every 10 seconds
        except Exception as e:
            print(f"{RED}❌ Memory monitoring error: {e}{RESET}")
            log_message(f"❌ Memory monitoring error: {e}")
            time.sleep(5)

def monitor_cpu_usage_of_processes():
    """Monitor CPU usage of all processes with severity levels"""
    global cpu_alert_counts
    
    while True:
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                if int(pid) == os.getpid():  # Skip your own monitoring script
                    continue

                cpu = get_cpu_usage_simple(pid)

                # Check different severity levels
                severity = None
                if cpu and cpu >= CPU_EXTREME_THRESHOLD:
                    severity = "EXTREME"
                elif cpu and cpu >= CPU_CRITICAL_THRESHOLD:
                    severity = "CRITICAL"
                elif cpu and cpu >= CPU_HIGH_THRESHOLD:
                    severity = "HIGH"

                if severity:
                    try:
                        with open(f"/proc/{pid}/cmdline", "r") as f:
                            cmd = f.read().replace('\x00', ' ').strip()

                        # Skip monitoring system processes (self-exclusion)
                        monitoring_keywords = [
                            "acm_monitor.py", "acm.py", "streamlit", "dashboard.py",
                            "monitor_env/bin/streamlit", "monitor_env/bin/python",
                            "/streamlit", "streamlit run"
                        ]
                        
                        if any(keyword in cmd for keyword in monitoring_keywords):
                            continue

                        name, ppid, uid = get_name_ppid_uid(pid)
                        user = get_username(uid) if uid is not None else "unknown"

                        # Extract script name for better display
                        script_name = extract_script_name_improved(cmd)
                        display_name = script_name if script_name else (name or "unknown")

                        cpu_alert_counts[pid] += 1
                        count = cpu_alert_counts[pid]
                        
                        # Get severity-specific formatting
                        color = SEVERITY_COLORS[severity]
                        emoji = SEVERITY_EMOJIS[severity]
                        severity_name = SEVERITY_NAMES[severity]
                        
                        timestamp = get_ist_datetime()
                        
                        # Enhanced alert message with severity
                        alert_msg = f"{CYAN}[{timestamp}] {color}{emoji} {severity_name} Process ({display_name}) PID {pid} x{count}: {cpu:.1f}% → {cmd}{RESET}"
                        
                        print(alert_msg)
                        
                        # Add special handling for critical and extreme cases
                        if severity == "CRITICAL":
                            print(f"{RED}  ⚠️  CRITICAL: Process consuming {cpu:.1f}% CPU - consider investigation{RESET}")
                        elif severity == "EXTREME":
                            print(f"{MAGENTA}  🚨 EXTREME: Process consuming {cpu:.1f}% CPU - immediate attention required!{RESET}")
                            print(f"{MAGENTA}  💀 This process may be causing system instability{RESET}")
                        
                        # Log to anomaly system with appropriate severity
                        log_anomaly(
                            process_name=display_name,
                            reason=f"{severity_name}: {cpu:.1f}% CPU usage",
                            pid=pid,
                            severity=severity,
                            user=user,
                            command=cmd
                        )

                    except (FileNotFoundError, PermissionError):
                        continue
                    except Exception as e:
                        if DEBUG_MODE:
                            print(f"{RED}❌ CPU monitoring error for PID {pid}: {e}{RESET}")

            time.sleep(5)  # Check every 5 seconds (faster than before)
            
        except Exception as e:
            print(f"{RED}❌ CPU monitoring error: {e}{RESET}")
            log_message(f"❌ CPU monitoring error: {e}")
            time.sleep(5)

def main():
    """Main monitoring loop"""
    global anomaly_logger, recent_processes, anomaly_buffer
    
    print(f"{GREEN}✅ Anomaly logger initialized successfully{RESET}")
    
    # Initialize anomaly logger
    anomaly_logger = AnomalyLogger(CSV_FILE)
    print(f"{GREEN}✅ Anomaly logger initialized successfully{RESET}")
    
    # Print startup information
    print(f"{CYAN}🖥️  Enhanced System Monitor with Dashboard Integration{RESET}")
    print(f"{BLUE}📊 Dashboard: streamlit run dashboard.py{RESET}")
    print(f"{YELLOW}📁 Anomalies file: {CSV_FILE}{RESET}")
    print(f"{MAGENTA}📄 Log file: {LOG_FILE}{RESET}")
    print("=" * 60)
    
    # Test log file writability
    try:
        log_message("🚀 NEW SESSION STARTED: " + get_ist_datetime())
        print(f"{GREEN}✅ Log file is writable: {LOG_FILE}{RESET}")
    except Exception as e:
        print(f"{RED}❌ Cannot write to log file: {e}{RESET}")
        return

    log_message("🔗 Enhanced System Monitor — Universal Process & Anomaly Detection")
    log_message("📌 Language-agnostic process burst detection active")
    log_message("📊 Dashboard integration enabled")
    
    # Start memory monitoring thread
    memory_thread = threading.Thread(target=monitor_memory_usage_of_processes, daemon=True)
    memory_thread.start()
    print(f"{GREEN}✅ Memory monitoring thread started{RESET}")
    
    # Start CPU monitoring thread
    cpu_thread = threading.Thread(target=monitor_cpu_usage_of_processes, daemon=True)
    cpu_thread.start()
    print(f"{GREEN}✅ CPU monitoring thread started{RESET}")
    
    print(f"{CYAN}🚀 Monitoring started - Press Ctrl+C to stop{RESET}")
    
    # Initialize variables for main loop
    last_grouped_alert_time = time.time()
    seen_processes = set()
    
    try:
        while True:
            current_processes = set()
            
            # Scan all current processes
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                
                try:
                    pid = int(pid)
                    if pid == os.getpid():  # Skip self
                        continue
                    
                    name, ppid, uid = get_name_ppid_uid(pid)
                    if not name:
                        continue
                    
                    current_processes.add(pid)
                    
                    # Check for new processes
                    if pid not in seen_processes:
                        user = get_username(uid) if uid is not None else "unknown"
                        cmd = get_cmdline(pid)
                        
                        # Record new process
                        recent_processes.append({
                            'pid': pid,
                            'name': name,
                            'ppid': ppid,
                            'user': user,
                            'cmd': cmd,
                            'time': time.time()
                        })
                        
                        # Always log process tree to file, print only in debug mode
                        print_process_tree(pid, name, user, cmd)
                        
                        seen_processes.add(pid)
                
                except (ValueError, FileNotFoundError, PermissionError):
                    continue
                except Exception as e:
                    if DEBUG_MODE:
                        print(f"{RED}❌ Error processing PID {pid}: {e}{RESET}")
            
            # Remove dead processes from seen set
            seen_processes &= current_processes
            
            # Check for process bursts
            now = time.time()
            recent_time_window = now - PROCESS_BURST_WINDOW
            
            # Get recent processes within time window
            recent = [p for p in recent_processes if p['time'] > recent_time_window]
            
            if len(recent) > PROCESS_BURST_THRESHOLD:
                # Group by parent process
                parent_groups = defaultdict(list)
                for process in recent:
                    parent_groups[process['ppid']].append(process)
                
                # Find the most prolific parent
                most_common_parent = max(parent_groups.keys(), key=lambda x: len(parent_groups[x]))
                most_common_count = len(parent_groups[most_common_parent])
                
                if DEBUG_MODE:
                    print(f"{YELLOW}[DEBUG] Anomaly Check → PID: {most_common_parent}, Count: {most_common_count}{RESET}")
                
                # Get parent process info
                try:
                    parent_name, _, parent_uid = get_name_ppid_uid(most_common_parent)
                    parent_user = get_username(parent_uid) if parent_uid is not None else "unknown"
                    parent_cmd = get_cmdline(most_common_parent)
                except:
                    parent_name, parent_user, parent_cmd = "unknown", "unknown", "N/A"
                
                # Check if it's a safe parent process
                if parent_name and parent_name in SAFE_PARENT_NAMES:
                    if DEBUG_MODE:
                        print(f"{YELLOW}[DEBUG] Burst from safe parent '{parent_name}' ignored.{RESET}")
                else:
                    # Check cooldown to avoid spam
                    burst_key = f"{most_common_parent}_{parent_name}"
                    last_alert_time = burst_alert_history.get(burst_key, 0)
                    
                    if now - last_alert_time > BURST_COOLDOWN:
                        # Find the instigator (a child process that's likely causing the burst)
                        children = parent_groups[most_common_parent]
                        instigator = children[0]  # Take the first spawned process as instigator
                        instigator_pid = instigator['pid']
                        name = instigator['name']
                        user = instigator['user']
                        
                        # Get better process name for display
                        cmd = get_cmdline(instigator_pid)
                        normalized_name = get_better_process_name(instigator_pid, name, cmd)
                        
                        # Get parent info for context
                        parent_info = get_parent_process_info(most_common_parent)
                        parent_context = ""
                        if parent_info and parent_info['name'] != normalized_name:
                            parent_script = extract_script_name_improved(parent_info['cmd'])
                            if parent_script:
                                parent_context = f" (spawned by {parent_script})"
                            elif parent_info['name'] not in ['bash', 'sh', 'dash']:
                                parent_context = f" (spawned by {parent_info['name']})"
                        
                        severity = "HIGH" if len(recent) > 15 else "MEDIUM"
                        
                        # Create anomaly entry
                        anomaly_entry = {
                            'type': 'PROCESS_BURST',
                            'time': now,
                            'pid': instigator_pid,
                            'name': normalized_name,
                            'count': len(recent),
                            'info': f"{normalized_name} (PID {instigator_pid}){parent_context}"
                        }
                        
                        anomaly_buffer.append(anomaly_entry)
                        
                        # Enhanced alert message
                        alert_msg = f"⚠️ PROCESS_BURST: {normalized_name} (PID {instigator_pid}){parent_context} - {len(recent)} processes spawned in {PROCESS_BURST_WINDOW}s"
                        print(f"{YELLOW}{alert_msg}{RESET}")
                        
                        # Show command details in debug mode
                        if DEBUG_MODE:
                            print(f"[DEBUG] Child command: {cmd}")
                            if parent_info:
                                print(f"[DEBUG] Parent command: {parent_info['cmd']}")
                        
                        # Log anomaly
                        log_anomaly(
                            process_name=normalized_name,
                            reason=f"Process burst: {len(recent)} processes spawned rapidly{parent_context}",
                            pid=instigator_pid,
                            severity=severity,
                            user=user,
                            command=cmd
                        )
                        
                        # Update cooldown
                        burst_alert_history[burst_key] = now
                    elif DEBUG_MODE:
                        print(f"{YELLOW}[DEBUG] Burst alert for {burst_key} in cooldown{RESET}")
            # Flush grouped anomaly buffer
            if time.time() - last_grouped_alert_time > ANOMALY_GROUP_WINDOW and anomaly_buffer:
                if len(anomaly_buffer) > 1:
                    print(f"\n{MAGENTA}⚠️  Multiple Anomalies Detected (Grouped):{RESET}")
                    for anomaly in anomaly_buffer:
                        time_str = time.strftime("%H:%M:%S", time.localtime(anomaly['time']))
                        print(f"• [{time_str}] PID {anomaly['pid']} → {anomaly['count']} spawns — {anomaly['info']}")
                
                anomaly_buffer.clear()
                last_grouped_alert_time = time.time()
            
            time.sleep(1)  # Main loop delay
            
    except KeyboardInterrupt:
        print(f"\n{YELLOW}🛑 Monitoring stopped by user{RESET}")
        log_message("🛑 Monitoring stopped by user")
    except Exception as e:
        error_msg = f"❌ Monitoring error: {e}"
        print(f"{RED}{error_msg}{RESET}")
        log_message(error_msg)
        
        # Log as suspicious activity
        log_anomaly(
            process_name="MONITOR",
            reason=error_msg,
            pid="",
            severity="HIGH",
            user="system",
            command=""
        )

if __name__ == "__main__":
    main()