from datetime import datetime, timedelta, timezone
import os
import pwd
import time
import signal
import sys
from collections import Counter

IST = timezone(timedelta(hours=5, minutes=30))

# ==== Debug Mode Toggle ====
DEBUG_MODE = True  # Set to False to suppress debug output

# Grouped anomaly detection buffer
anomaly_buffer = []
last_grouped_alert_time = time.time()
ANOMALY_GROUP_WINDOW = 5  # seconds

CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

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

    time.sleep(1)