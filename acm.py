from datetime import datetime, timedelta, timezone
import os
import pwd
import time
import signal
import sys
from collections import Counter
import re 

IST = timezone(timedelta(hours=5, minutes=30))

# ==== Debug Mode Toggle ====
DEBUG_MODE = False  # Set to False to suppress debug output

# Grouped anomaly detection buffer
anomaly_buffer = []
last_grouped_alert_time = time.time()
ANOMALY_GROUP_WINDOW = 5  # seconds

CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
GREEN = "\033[92m"
MAGENTA = "\033[95m"
BLINK = "\033[5m"
BOLD = "\033[1m"

cpu_samples = {}  # {pid: [cpu_usage_samples]}
cpu_alert_states = {}  # {pid: {'consecutive_high': int, 'last_alert': float, 'critical_start': float}}
system_cpu_samples = []  # System-wide CPU usage samples
system_cpu_alert_state = {'consecutive_high': 0, 'last_alert': 0, 'overload_start': 0}
prev_system_stats = None
prev_process_stats = {}  # {pid: (utime, stime, total_time)}
CPU_SAMPLE_WINDOW = 10  # Keep last 10 samples
last_cpu_check = time.time()
cpu_alert_groups = {}  # {(pid, alert_type): {'count': int, 'first_time': float, 'last_time': float, 'info': dict}}
last_cpu_group_flush = time.time()
CPU_GROUP_WINDOW = 3  # Group similar alerts for 3 seconds
CPU_GROUP_COOLDOWN = 10  # Don't repeat same alert for 10 seconds

# Setup log file - save in current working directory (same as script)
log_path = "netsnoop_persistent.txt"
print(f"Log file will be created in current directory: {os.getcwd()}")
print(f"Full log file path: {os.path.abspath(log_path)}")

def get_current_time_str():
    """Get current time formatted in IST timezone"""
    return datetime.now(IST).strftime('%Y-%m-%d %H:%M:%S %Z')

def get_short_time_str():
    """Get current time in short format for process logs"""
    return datetime.now(IST).strftime('%H:%M:%S')

def log(text):
    # For process detection logs that already have timestamps, don't add another
    if text.startswith("[") and "] 🔧 New Process Detected:" in text:
        timestamped_text = text
    else:
        # For other logs (like startup messages), add timestamp
        timestamp = get_current_time_str()
        timestamped_text = f"[{timestamp}] {text}"
    
    if DEBUG_MODE:
        print(timestamped_text)
    
    # Write to file with error handling
    try:
        with open(log_path, "a", encoding='utf-8') as f:
            f.write(timestamped_text + "\n")
            f.flush()  # Force write to disk
        if DEBUG_MODE and "SESSION STARTED" in text:
            print(f"✅ Successfully wrote to log file: {log_path}")
    except Exception as e:
        print(f"❌ Error writing to log file {log_path}: {e}")
        # Try writing to current directory as fallback
        try:
            fallback_path = "netsnoop_persistent2.txt"
            with open(fallback_path, "a", encoding='utf-8') as f:
                f.write(timestamped_text + "\n")
                f.flush()
            print(f"✅ Fallback: wrote to {fallback_path}")
        except Exception as e2:
            print(f"❌ Fallback also failed: {e2}")

def get_username(uid):
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except:
        return "unknown"

def get_name_ppid_uid(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            lines = f.readlines()
        name = ppid = uid = ""
        for line in lines:
            if line.startswith("Name:"):
                name = line.split()[1]
            elif line.startswith("PPid:"):
                ppid = line.split()[1]
            elif line.startswith("Uid:"):
                uid = line.split()[1]
        return name, ppid, uid
    except:
        return None, None, None

def build_process_chain(pid):
    chain = []
    while pid != "0" and pid != "1":
        name, ppid, uid = get_name_ppid_uid(pid)
        if not name:
            break
        chain.append((name, pid, get_username(uid)))
        pid = ppid
    root = get_name_ppid_uid(pid)
    if root[0]:
        chain.append((root[0], pid, get_username(root[2])))
    return list(reversed(chain))

def get_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            args = f.read().replace(b'\x00', b' ').decode().strip()
            return args or "N/A"
    except:
        return "N/A"

def get_exe_path(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except:
        return "N/A"

def list_pids():
    return [pid for pid in os.listdir("/proc") if pid.isdigit()]

# ALL THESE CPU FUNCTIONS HERE:
def get_system_cpu_stats():
    """Get system CPU stats from /proc/stat"""
    try:
        with open('/proc/stat', 'r') as f:
            line = f.readline()
        # cpu  user nice system idle iowait irq softirq steal guest guest_nice
        values = line.split()[1:]
        stats = {
            'user': int(values[0]),
            'nice': int(values[1]),
            'system': int(values[2]),
            'idle': int(values[3]),
            'iowait': int(values[4]),
            'irq': int(values[5]),
            'softirq': int(values[6]),
            'steal': int(values[7]) if len(values) > 7 else 0
        }
        stats['total'] = sum(stats.values())
        stats['active'] = stats['total'] - stats['idle'] - stats['iowait']
        return stats
    except:
        return None

def get_process_cpu_stats(pid):
    """Get process CPU stats from /proc/[pid]/stat"""
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            fields = f.readline().split()
        # utime is field 14 (index 13), stime is field 15 (index 14)
        utime = int(fields[13])  # User time
        stime = int(fields[14])  # System time
        total_time = utime + stime
        return utime, stime, total_time
    except:
        return None

def get_load_average():
    """Get system load average from /proc/loadavg"""
    try:
        with open('/proc/loadavg', 'r') as f:
            line = f.readline().strip()
        # Format: 0.52 0.58 0.59 2/254 12345
        parts = line.split()
        return {
            '1min': float(parts[0]),
            '5min': float(parts[1]),
            '15min': float(parts[2]),
            'running_processes': int(parts[3].split('/')[0]),
            'total_processes': int(parts[3].split('/')[1])
        }
    except:
        return None

def calculate_cpu_usage(prev_stats, curr_stats):
    """Calculate CPU usage percentage from two stat snapshots"""
    if not prev_stats or not curr_stats:
        return 0.0
    
    total_diff = curr_stats['total'] - prev_stats['total']
    active_diff = curr_stats['active'] - prev_stats['active']
    
    if total_diff <= 0:
        return 0.0
    
    cpu_percent = (active_diff / total_diff) * 100.0
    return min(100.0, max(0.0, cpu_percent))

def calculate_process_cpu_usage(pid, prev_proc_stats, curr_proc_stats, prev_sys_stats, curr_sys_stats):
    """Calculate process CPU usage percentage"""
    if not all([prev_proc_stats, curr_proc_stats, prev_sys_stats, curr_sys_stats]):
        return 0.0
    
    proc_total_diff = curr_proc_stats[2] - prev_proc_stats[2]  # total_time difference
    sys_total_diff = curr_sys_stats['total'] - prev_sys_stats['total']
    
    if sys_total_diff <= 0:
        return 0.0
    
    # Get number of CPU cores
    try:
        with open('/proc/cpuinfo', 'r') as f:
            cpu_count = len([line for line in f if line.startswith('processor')])
    except:
        cpu_count = 1
    
    # Calculate CPU percentage
    cpu_percent = (proc_total_diff / sys_total_diff) * 100.0 * cpu_count
    return min(100.0, max(0.0, cpu_percent))

# REPLACE YOUR ENTIRE check_cpu_anomalies() FUNCTION WITH THIS:

def check_cpu_anomalies():
    """Check for CPU overload anomalies with intelligent grouping"""
    global prev_system_stats, prev_process_stats, last_cpu_check, cpu_alert_groups, last_cpu_group_flush
    
    now = time.time()
    if now - last_cpu_check < 1.0:  # Check every second
        return
    
    last_cpu_check = now
    current_time_str = get_current_time_str()
    
    # Get current system stats
    curr_system_stats = get_system_cpu_stats()
    if not curr_system_stats:
        return
    
    # Calculate system-wide CPU usage
    if prev_system_stats:
        system_cpu_usage = calculate_cpu_usage(prev_system_stats, curr_system_stats)
        
        # Add to system CPU samples
        system_cpu_samples.append(system_cpu_usage)
        if len(system_cpu_samples) > CPU_SAMPLE_WINDOW:
            system_cpu_samples.pop(0)
        
        # Check system-wide CPU anomalies (keep immediate for system alerts)
        if system_cpu_usage > 95.0:
            if system_cpu_alert_state['overload_start'] == 0:
                system_cpu_alert_state['overload_start'] = now
            elif now - system_cpu_alert_state['overload_start'] >= 5.0:
                # Critical system overload
                load_avg = get_load_average()
                load_info = f"Load: {load_avg['1min']:.2f}" if load_avg else "Load: N/A"
                
                alert_msg = f"{BLINK}{BOLD}{RED}🚨 CRITICAL SYSTEM OVERLOAD: {system_cpu_usage:.1f}% CPU, {load_info}{RESET}"
                print(alert_msg)
                log(f"🚨 CRITICAL SYSTEM OVERLOAD: {system_cpu_usage:.1f}% CPU, {load_info}")
                
        elif system_cpu_usage > 90.0:
            system_cpu_alert_state['consecutive_high'] += 1
            if system_cpu_alert_state['consecutive_high'] >= 5 and now - system_cpu_alert_state['last_alert'] > 10:
                load_avg = get_load_average()
                load_info = f"Load: {load_avg['1min']:.2f}" if load_avg else "Load: N/A"
                
                alert_msg = f"{BOLD}{RED}🔺 SYSTEM CPU ALERT: {system_cpu_usage:.1f}% for {system_cpu_alert_state['consecutive_high']}s, {load_info}{RESET}"
                print(alert_msg)
                log(f"🔺 SYSTEM CPU ALERT: {system_cpu_usage:.1f}% for {system_cpu_alert_state['consecutive_high']}s, {load_info}")
                system_cpu_alert_state['last_alert'] = now
        else:
            system_cpu_alert_state['consecutive_high'] = 0
            system_cpu_alert_state['overload_start'] = 0
    
    # Check per-process CPU usage
    current_pids = set(list_pids())
    curr_process_stats = {}
    
    for pid in current_pids:
        proc_stats = get_process_cpu_stats(pid)
        if proc_stats:
            curr_process_stats[pid] = proc_stats
            
            # Calculate process CPU usage if we have previous stats
            if pid in prev_process_stats and prev_system_stats:
                proc_cpu_usage = calculate_process_cpu_usage(
                    pid, prev_process_stats[pid], proc_stats, 
                    prev_system_stats, curr_system_stats
                )
                
                # Initialize tracking for new processes
                if pid not in cpu_samples:
                    cpu_samples[pid] = []
                    cpu_alert_states[pid] = {'consecutive_high': 0, 'last_alert': 0, 'critical_start': 0}
                
                # Add to samples
                cpu_samples[pid].append(proc_cpu_usage)
                if len(cpu_samples[pid]) > CPU_SAMPLE_WINDOW:
                    cpu_samples[pid].pop(0)
                
                # Get process info for alerts
                name, _, uid = get_name_ppid_uid(pid)
                user = get_username(uid) if uid else "unknown"
                cmd = get_cmdline(pid)
                
                # Create short command for display
                display_cmd = cmd
                if len(cmd) > 45:
                    display_cmd = cmd[:42] + "..."
                
                # Helper function to add alert to group
                def add_to_group(alert_type, alert_info):
                    group_key = (pid, alert_type)
                    if group_key not in cpu_alert_groups:
                        cpu_alert_groups[group_key] = {
                            'count': 0,
                            'first_time': now,
                            'last_time': now,
                            'info': alert_info,
                            'max_cpu': proc_cpu_usage
                        }
                    
                    cpu_alert_groups[group_key]['count'] += 1
                    cpu_alert_groups[group_key]['last_time'] = now
                    cpu_alert_groups[group_key]['max_cpu'] = max(cpu_alert_groups[group_key]['max_cpu'], proc_cpu_usage)
                
                # Check for anomalies and group them
                if proc_cpu_usage > 95.0:
                    # Critical CPU usage
                    if cpu_alert_states[pid]['critical_start'] == 0:
                        cpu_alert_states[pid]['critical_start'] = now
                    elif now - cpu_alert_states[pid]['critical_start'] >= 5.0:
                        # Add to group instead of immediate alert
                        add_to_group('CRITICAL', {
                            'pid': pid,
                            'name': name,
                            'user': user,
                            'cmd': cmd,
                            'display_cmd': display_cmd,
                            'duration': '5+s'
                        })
                        cpu_alert_states[pid]['last_alert'] = now
                        
                elif proc_cpu_usage > 90.0:
                    # Suspicious spike
                    if now - cpu_alert_states[pid]['last_alert'] > 5:  # Don't spam
                        add_to_group('SUSPICIOUS', {
                            'pid': pid,
                            'name': name,
                            'user': user,
                            'cmd': cmd,
                            'display_cmd': display_cmd
                        })
                        cpu_alert_states[pid]['last_alert'] = now
                        
                elif proc_cpu_usage > 80.0:
                    # High CPU usage - track consecutive samples
                    cpu_alert_states[pid]['consecutive_high'] += 1
                    if cpu_alert_states[pid]['consecutive_high'] >= 3 and now - cpu_alert_states[pid]['last_alert'] > 10:
                        add_to_group('HIGH', {
                            'pid': pid,
                            'name': name,
                            'user': user,
                            'cmd': cmd,
                            'display_cmd': display_cmd,
                            'duration': f"{cpu_alert_states[pid]['consecutive_high']}s"
                        })
                        cpu_alert_states[pid]['last_alert'] = now
                else:
                    # Reset counters for normal CPU usage
                    cpu_alert_states[pid]['consecutive_high'] = 0
                    cpu_alert_states[pid]['critical_start'] = 0
    
    # Process and display grouped CPU alerts
    if now - last_cpu_group_flush > CPU_GROUP_WINDOW:
        display_grouped_cpu_alerts()
        last_cpu_group_flush = now
    
    # Clean up old process data
    active_pids = set(current_pids)
    for pid in list(cpu_samples.keys()):
        if pid not in active_pids:
            del cpu_samples[pid]
            if pid in cpu_alert_states:
                del cpu_alert_states[pid]
            if pid in prev_process_stats:
                del prev_process_stats[pid]
    
    # Update previous stats for next iteration
    prev_system_stats = curr_system_stats
    prev_process_stats = curr_process_stats
def display_grouped_cpu_alerts():
    """Display grouped CPU alerts in a clean format"""
    global cpu_alert_groups
    
    if not cpu_alert_groups:
        return
    
    # Organize alerts by type and process
    alert_types = {'CRITICAL': [], 'SUSPICIOUS': [], 'HIGH': []}
    
    for (pid, alert_type), group_data in cpu_alert_groups.items():
        info = group_data['info']
        count = group_data['count']
        max_cpu = group_data['max_cpu']
        duration = group_data['last_time'] - group_data['first_time']
        
        # Format the alert message
        if alert_type == 'CRITICAL':
            if count == 1:
                msg = f"🧨 CRITICAL CPU: PID {pid} ({info['name']}) {max_cpu:.1f}% for {info.get('duration', '5+s')} → {info['display_cmd']}"
                color = f"{BLINK}{BOLD}{RED}"
            else:
                msg = f"🧨 CRITICAL CPU: PID {pid} ({info['name']}) {max_cpu:.1f}% for {duration:.0f}s ({count}x alerts) → {info['display_cmd']}"
                color = f"{BLINK}{BOLD}{RED}"
        
        elif alert_type == 'SUSPICIOUS':
            if count == 1:
                msg = f"🚩 SUSPICIOUS CPU SPIKE: PID {pid} ({info['name']}) {max_cpu:.1f}% → {info['display_cmd']}"
                color = f"{BOLD}{YELLOW}"
            else:
                msg = f"🚩 SUSPICIOUS CPU SPIKES: PID {pid} ({info['name']}) {max_cpu:.1f}% ({count}x spikes) → {info['display_cmd']}"
                color = f"{BOLD}{YELLOW}"
        
        elif alert_type == 'HIGH':
            if count == 1:
                msg = f"🔺 HIGH CPU ALERT: PID {pid} ({info['name']}) {max_cpu:.1f}% for {info.get('duration', '3s')} → {info['display_cmd']}"
                color = f"{BOLD}{MAGENTA}"
            else:
                msg = f"🔺 HIGH CPU ALERTS: PID {pid} ({info['name']}) {max_cpu:.1f}% for {duration:.0f}s ({count}x alerts) → {info['display_cmd']}"
                color = f"{BOLD}{MAGENTA}"
        
        alert_types[alert_type].append((color, msg, info))
    
    # Display alerts in order of severity
    for alert_type in ['CRITICAL', 'SUSPICIOUS', 'HIGH']:
        for color, msg, info in alert_types[alert_type]:
            print(f"{color}{msg}{RESET}")
            
            # Log to file with full details
            if alert_type == 'CRITICAL':
                log(f"🧨 CRITICAL CPU: PID {info['pid']} ({info['name']}, User: {info['user']}) - Command: {info['cmd']}")
            elif alert_type == 'SUSPICIOUS':
                log(f"🚩 SUSPICIOUS CPU SPIKE: PID {info['pid']} ({info['name']}, User: {info['user']}) - Command: {info['cmd']}")
            elif alert_type == 'HIGH':
                log(f"🔺 HIGH CPU ALERT: PID {info['pid']} ({info['name']}, User: {info['user']}) - Command: {info['cmd']}")
    
    # Clear the groups
    cpu_alert_groups.clear()


#SYSTEM PROCESS BURSTS FUNCTION
def trace_to_real_instigator(pid):
    visited = set()
    best_match = None
    original_pid = pid  # Keep track of the original PID
    ancestral_processes = []  # Store all processes in the chain
    
    # Find all interesting (non-system) processes that might be instigators
    def find_potential_instigators():
        potential_procs = []
        try:
            for check_pid in list_pids():
                cmd = get_cmdline(check_pid)
                name, _, _ = get_name_ppid_uid(check_pid)
                
                # Look for any user-space programs that could be instigators
                if (name and cmd and cmd != "N/A" and 
                    not name.lower().startswith(("systemd", "init", "relay", "sessionleader", "kernel")) and
                    not cmd.startswith(("/usr/lib/systemd", "/sbin/", "kernel")) and
                    "acm.py" not in cmd and "netsnoop" not in cmd.lower()):  # Exclude our monitoring script
                    
                    # Prioritize certain types of programs
                    priority = 0
                    if any(ext in cmd for ext in [".py", ".sh", ".pl", ".rb", ".js", ".c", ".cpp", ".go"]):  # Scripts/source files
                        priority = 3
                    elif any(lang in cmd.lower() for lang in ["python", "node", "java", "go", "rust", "gcc", "make", "cmake"]):  # Interpreters/runtimes/build tools
                        priority = 2
                    elif "/" not in cmd or not cmd.startswith("/usr/bin/"):  # Custom binaries
                        priority = 1
                    
                    potential_procs.append((priority, f"{cmd} (PID {check_pid})", check_pid))
        except:
            pass
        
        # Sort by priority (highest first)
        return sorted(potential_procs, key=lambda x: x[0], reverse=True)

    # First, try tracing up the process tree to find meaningful programs
    current_pid = pid
    while current_pid and current_pid != "0" and current_pid != "1" and current_pid not in visited:
        visited.add(current_pid)
        cmd = get_cmdline(current_pid)
        name, ppid, _ = get_name_ppid_uid(current_pid)

        if DEBUG_MODE:
            print(f"[TRACE] Checking PID {current_pid}: {name} -> {cmd}")

        # Store this process in our ancestral chain
        if name and cmd != "N/A":
            ancestral_processes.append((name, cmd, current_pid))

        # Look for any meaningful program (not just Python)
        if (cmd and cmd != "N/A" and 
            not name.lower().startswith(("systemd", "init", "relay", "sessionleader")) and
            not cmd.startswith(("/usr/lib/systemd", "/sbin/")) and
            "acm.py" not in cmd and "netsnoop" not in cmd.lower()):
            
            # Check if this looks like a user program that could spawn processes
            if (any(ext in cmd for ext in [".py", ".sh", ".pl", ".rb", ".js", ".c", ".cpp", ".go"]) or  # Script/source files
                any(lang in cmd.lower() for lang in ["python", "node", "java", "go", "rust", "gcc", "make", "cmake"]) or  # Runtimes/compilers
                ("/" not in cmd or not cmd.startswith("/usr/bin/")) or  # Custom binaries
                any(keyword in cmd.lower() for keyword in ["build", "compile", "test", "run", "stress"])):  # Build/test tools
                
                return f"{cmd} (PID {current_pid})"
        
        # Continue traversing up the tree
        current_pid = ppid

    # If direct tracing failed, look for potential instigators running currently
    potential_instigators = find_potential_instigators()
    if potential_instigators:
        if DEBUG_MODE:
            print(f"[TRACE] Found potential instigators: {[p[1] for p in potential_instigators[:3]]}")
        
        # Try to find one that's related to the original process by checking session/parent relationships
        for priority, instigator_desc, instigator_pid in potential_instigators:
            try:
                instigator_chain = build_process_chain(str(instigator_pid))
                original_chain = build_process_chain(original_pid)
                
                # Look for common session leaders, relay processes, or bash sessions
                for i_name, i_pid, i_user in instigator_chain:
                    for o_name, o_pid, o_user in original_chain:
                        if (i_pid == o_pid and 
                            ("SessionLeader" in i_name or "Relay" in i_name or "bash" in i_name)):
                            if DEBUG_MODE:
                                print(f"[TRACE] Found related instigator through common parent {i_name} (PID {i_pid})")
                            return instigator_desc
            except:
                continue
        
        # If no direct relationship found, return the highest priority instigator
        return f"Likely instigator: {potential_instigators[0][1]}"

    # Find the most meaningful ancestral process (skip system processes)
    meaningful_processes = []
    for name, cmd, proc_pid in ancestral_processes:
        # Skip obvious system/wrapper processes
        if (not name.lower().startswith(("systemd", "init", "relay", "sessionleader")) and 
            cmd not in ["N/A", ""] and 
            not cmd.startswith(("/usr/lib/systemd", "/sbin/"))):
            meaningful_processes.append((name, cmd, proc_pid))
    
    # Return the first meaningful process we found
    if meaningful_processes:
        name, cmd, proc_pid = meaningful_processes[0]
        return f"{name} - {cmd} (PID {proc_pid})"
    
    # If all else fails, return the deepest non-system process we found
    if ancestral_processes:
        name, cmd, proc_pid = ancestral_processes[0]  # First (deepest) in chain
        return f"{name} - {cmd} (PID {proc_pid})"
    
    # Last resort - return original process info
    original_name, _, _ = get_name_ppid_uid(original_pid)
    original_cmd = get_cmdline(original_pid)
    if original_name:
        return f"{original_name} - {original_cmd} (PID {original_pid})"
    else:
        return f"Unknown process (PID {original_pid})"

seen_pids = set()
pid_spawn_times = {}

burst_threshold = 8  # Number of processes (lowered to be more sensitive)
burst_window = 3      # Seconds (increased window slightly)

SAFE_PARENT_NAMES = {
    "systemd", "init", "rsyslogd", "cron", "agetty", "dbus-daemon",
    "systemd-journal", "systemd-resolve", "systemd-timesyn", "unattended-upgr",
    "systemd-udevd", "wsl-pro-service", "bash", "login", "(sd-pam)", 
    "init-systemd(Ub"
    # Note: Relay processes are handled specially in anomaly detection
}

# Test file creation
try:
    with open(log_path, "a", encoding='utf-8') as f:
        f.write("")  # Just test if we can write
    print(f"✅ Log file is writable: {log_path}")
except Exception as e:
    print(f"❌ Cannot write to log file: {e}")
    print("Check file permissions in current directory")

# Session end handler
def signal_handler(sig, frame):
    # Display any remaining grouped alerts before exit
    display_grouped_cpu_alerts()
    
    session_end_time = get_current_time_str()
    end_separator = f"\n🛑 SESSION ENDED: {session_end_time}\n{'='*80}\n"
    log(end_separator)
    sys.exit(0)

# Register signal handler for graceful shutdown
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Start log - add session separator
session_start_time = get_current_time_str()
session_separator = f"\n{'='*80}\n🚀 NEW SESSION STARTED: {session_start_time}\n{'='*80}"
log(session_separator)
log(f"{CYAN}🔗 NetSnoop — Universal Process Monitor & Anomaly Detection{RESET}")
log("📌 Language-agnostic process burst detection active")

while True:
    now = time.time()
    current_pids = set(list_pids())
    new_pids = current_pids - seen_pids

    for pid in new_pids:
        seen_pids.add(pid)
        pid_spawn_times[pid] = now

        chain = build_process_chain(pid)

        output = [f"[{get_short_time_str()}] 🔧 New Process Detected:"]
        for i, (name, pid_, user) in enumerate(chain):
            indent = "    " * i + "└── "
            output.append(f"{indent}{name} (PID {pid_}, User: {user})")
        sub_indent = "    " * len(chain)
        if chain and len(chain[-1]) > 1:
            output.append(f"{sub_indent}├── Executable: {get_exe_path(chain[-1][1])}")
        else:
            output.append(f"{sub_indent}├── Executable: N/A")

        if chain and len(chain[-1]) > 1:
            output.append(f"{sub_indent}└── CmdLine: {get_cmdline(chain[-1][1])}")
        else:
            output.append(f"{sub_indent}└── CmdLine: N/A")

        log("\n".join(output))

    # Anomaly Detection
    recent = {pid: ts for pid, ts in pid_spawn_times.items() if now - ts <= burst_window}

    if len(recent) > burst_threshold:
        # Get parent PIDs, but filter out None values
        ppids = []
        for pid in recent:
            name, ppid, _ = get_name_ppid_uid(pid)
            if ppid and ppid != "0":  # Filter out None and "0" (kernel processes)
                ppids.append(ppid)
        
        if ppids:  # Only proceed if we have valid parent PIDs
            ppid_counts = Counter(ppids)
            instigator_pid, count = ppid_counts.most_common(1)[0]
            name, _, _ = get_name_ppid_uid(instigator_pid)

            if DEBUG_MODE:
                print(f"[DEBUG] Anomaly Check → PID: {instigator_pid}, Name: {name}")
                print(f"[DEBUG] Recent processes: {len(recent)}, Most common parent: {instigator_pid} ({count} children)")
                
                # Debug: Show all current user processes
                print(f"[DEBUG] All current user processes:")
                try:
                    for check_pid in list_pids():
                        cmd = get_cmdline(check_pid)
                        proc_name, _, _ = get_name_ppid_uid(check_pid)
                        if (cmd and cmd != "N/A" and proc_name and
                            not proc_name.lower().startswith(("systemd", "init", "relay", "sessionleader")) and
                            not cmd.startswith(("/usr/lib/systemd", "/sbin/"))):
                            print(f"[DEBUG]   - PID {check_pid}: {cmd}")
                except:
                    print(f"[DEBUG]   - Error listing user processes")

            if name:
                normalized_name = name.strip().split("(")[0]
                if normalized_name not in SAFE_PARENT_NAMES:
                    # Always try to trace to find the real instigator, regardless of immediate parent
                    instigator_cmd = trace_to_real_instigator(instigator_pid)
                    
                    # If we still don't have a good result, look for meaningful processes in the spawn chain
                    if not instigator_cmd or "Unknown process" in str(instigator_cmd) or "Relay" in str(instigator_cmd):
                        # Check if any of the recently spawned processes are from a meaningful parent
                        meaningful_found = False
                        for pid in recent:
                            parent_chain = build_process_chain(pid)
                            for proc_name, proc_pid, proc_user in parent_chain:
                                cmd = get_cmdline(proc_pid)
                                # Look for any user program that could be an instigator
                                if (cmd and cmd != "N/A" and 
                                    not proc_name.lower().startswith(("systemd", "init", "relay", "sessionleader")) and
                                    not cmd.startswith(("/usr/lib/systemd", "/sbin/")) and
                                    "acm.py" not in cmd and "netsnoop" not in cmd.lower()):
                                    
                                    # Check if it's a script, compiler, or user binary
                                    if (any(ext in cmd for ext in [".py", ".sh", ".pl", ".rb", ".js", ".c", ".cpp", ".go"]) or
                                        any(lang in cmd.lower() for lang in ["python", "node", "java", "go", "rust", "gcc", "make", "cmake"]) or
                                        ("/" not in cmd or not cmd.startswith("/usr/bin/"))):
                                        
                                        instigator_cmd = f"{cmd} (PID {proc_pid})"
                                        if DEBUG_MODE:
                                            print(f"[DEBUG] Found meaningful instigator in chain: {instigator_cmd}")
                                        meaningful_found = True
                                        break
                                if meaningful_found:
                                    break
                            if meaningful_found:
                                break
                        
                        # Alternative approach: Look for currently running user processes that might be related
                        if not meaningful_found:
                            try:
                                for check_pid in list_pids():
                                    cmd = get_cmdline(check_pid)
                                    proc_name, _, _ = get_name_ppid_uid(check_pid)
                                    
                                    # Look for user programs (not system processes)
                                    if (cmd and cmd != "N/A" and proc_name and
                                        not proc_name.lower().startswith(("systemd", "init", "relay", "sessionleader")) and
                                        not cmd.startswith(("/usr/lib/systemd", "/sbin/")) and
                                        "acm.py" not in cmd and "netsnoop" not in cmd.lower()):
                                        
                                        # Check if this process is in the same session as the burst
                                        try:
                                            proc_chain = build_process_chain(check_pid)
                                            for chain_name, chain_pid, chain_user in proc_chain:
                                                if chain_pid == instigator_pid or any(chain_pid == get_name_ppid_uid(recent_pid)[1] for recent_pid in recent):
                                                    instigator_cmd = f"{cmd} (PID {check_pid})"
                                                    if DEBUG_MODE:
                                                        print(f"[DEBUG] Found related user process: {instigator_cmd}")
                                                    meaningful_found = True
                                                    break
                                            if meaningful_found:
                                                break
                                        except:
                                            continue
                            except Exception as e:
                                if DEBUG_MODE:
                                    print(f"[DEBUG] Error searching for related user processes: {e}")
                    
                    # Handle case where instigator_cmd is still None or not helpful
                    if not instigator_cmd or "Unknown process" in str(instigator_cmd):
                        instigator_cmd = f"{normalized_name} - {get_cmdline(instigator_pid)} (PID {instigator_pid})"

                    # 🔍 Optional: log full process chain for debug
                    if DEBUG_MODE:
                        chain = build_process_chain(instigator_pid)
                        debug_chain = []
                        for i, (n, p, u) in enumerate(chain):
                            indent = "    " * i
                            debug_chain.append(f"{indent}└─ {n} (PID {p}, User: {u})")
                        log("\n".join(debug_chain))

                    anomaly_buffer.append({
                        "timestamp": datetime.now(IST),
                        "num_procs": len(recent),
                        "instigator_pid": instigator_pid or "?",
                        "instigator_cmd": instigator_cmd,
                        "instigator_info": instigator_cmd if instigator_cmd else f"{normalized_name} ({get_cmdline(instigator_pid)})"
                    })

                else:
                    if DEBUG_MODE:
                        print(f"[DEBUG] Burst from safe parent '{normalized_name}' ignored.")
            else:
                if DEBUG_MODE:
                    print(f"[DEBUG] Skipping anomaly check — name is None for PID {instigator_pid}")
        else:
            if DEBUG_MODE:
                print(f"[DEBUG] No valid parent PIDs found in recent process burst")

    # Flush grouped anomaly buffer every 5 seconds
    if time.time() - last_grouped_alert_time > ANOMALY_GROUP_WINDOW and anomaly_buffer:
        alert_time = get_current_time_str()
        print(f"\n{RED}⚠️  Multiple Anomalies Detected (Grouped):{RESET}")
        
        # Log anomalies with proper timestamps
        log(f"{RED}⚠️  Multiple Anomalies Detected (Grouped):{RESET}")
        for event in anomaly_buffer:
            ts = event["timestamp"].strftime("%H:%M:%S")
            anomaly_text = f"  • [{ts}] PID {event['instigator_pid']} → {event['num_procs']} spawns — {event['instigator_info']}"
            print(f"{YELLOW}{anomaly_text}{RESET}")
            log(anomaly_text)
        
        print()
        anomaly_buffer.clear()
        last_grouped_alert_time = time.time()

    check_cpu_anomalies()

    time.sleep(1)