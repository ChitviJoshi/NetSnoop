import csv
import os
import time
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any

IST = timezone(timedelta(hours=5, minutes=30))

class AnomalyLogger:
    """Enhanced anomaly logging system for system monitoring dashboard"""
    
    def __init__(self, csv_file: str = "anomalies.csv", log_file: str = "system_monitor.log"):
        self.csv_file = csv_file
        self.log_file = log_file
        self.lock = threading.Lock()
        
        # Initialize CSV file with comprehensive headers
        self.csv_headers = [
            
            "timestamp",
            "anomaly_type", 
            "severity",
            "process_name",
            "pid",
            "user",
            "command",
            "description",
            "cpu_usage",
            "memory_usage_mb",
            "duration",
            "parent_pid",
            "session_id",
            "additional_info"
        ]
        
        self.initialize_files()
        
        # Anomaly type categories
        self.ANOMALY_TYPES = {
            "PROCESS_BURST": "Process Burst",
            "HIGH_CPU": "High CPU Usage",
            "CRITICAL_CPU": "Critical CPU Usage", 
            "HIGH_MEMORY": "High Memory Usage",
            "CRITICAL_MEMORY": "Critical Memory Usage",
            "SUSPICIOUS_PROCESS": "Suspicious Process",
            "USB_EVENT": "USB Device Event",
            "SYSTEM_OVERLOAD": "System Overload",
            "NETWORK_ANOMALY": "Network Anomaly",
            "FILE_ACCESS": "Suspicious File Access",
            "PRIVILEGE_ESCALATION": "Privilege Escalation"
        }
        
        # Severity levels
        self.SEVERITY_LEVELS = {
            "LOW": 1,
            "MEDIUM": 2, 
            "HIGH": 3,
            "CRITICAL": 4,
            "EMERGENCY": 5
        }
    
    def initialize_files(self):
        """Initialize CSV and log files with proper headers"""
        try:
            # Initialize CSV file if it doesn't exist
            if not os.path.exists(self.csv_file):
                with open(self.csv_file, "w", newline="", encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=self.csv_headers)
                    writer.writeheader()
                print(f"✅ Created anomaly CSV file: {self.csv_file}")
            
            # Test CSV file is writable
            with open(self.csv_file, "a", encoding='utf-8') as f:
                pass
                
            print(f"✅ Anomaly logger initialized successfully")
            
        except Exception as e:
            print(f"❌ Error initializing anomaly logger: {e}")
            raise
    
    def log_anomaly(self, 
                   anomaly_type: str,
                   process_name: str = "",
                   pid: str = "",
                   description: str = "",
                   severity: str = "MEDIUM",
                   user: str = "",
                   command: str = "",
                   cpu_usage: float = 0.0,
                   memory_usage_mb: float = 0.0,
                   duration: str = "",
                   parent_pid: str = "",
                   additional_info: str = ""):
        """
        Log an anomaly to CSV file with comprehensive details
        
        Args:
            anomaly_type: Type of anomaly (use ANOMALY_TYPES keys)
            process_name: Name of the process involved
            pid: Process ID
            description: Detailed description of the anomaly
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL, EMERGENCY)
            user: User running the process
            command: Full command line
            cpu_usage: CPU usage percentage
            memory_usage_mb: Memory usage in MB
            duration: Duration of the anomaly
            parent_pid: Parent process ID
            additional_info: Any additional context
        """
        
        with self.lock:
            try:
                timestamp = datetime.now(IST).strftime('%Y-%m-%d %H:%M:%S')
                
                # Generate session ID based on current time (for grouping related events)
                session_id = datetime.now(IST).strftime('%Y%m%d_%H')
                
                anomaly_data = {
                    "timestamp": timestamp,
                    "anomaly_type": self.ANOMALY_TYPES.get(anomaly_type, anomaly_type),
                    "severity": severity,
                    "process_name": process_name,
                    "pid": pid,
                    "user": user,
                    "command": command[:200] if command else "",  # Truncate long commands
                    "description": description,
                    "cpu_usage": cpu_usage,
                    "memory_usage_mb": memory_usage_mb,
                    "duration": duration,
                    "parent_pid": parent_pid,
                    "session_id": session_id,
                    "additional_info": additional_info
                }
                
                # Write to CSV file
                with open(self.csv_file, "a", newline="", encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=self.csv_headers)
                    writer.writerow(anomaly_data)
                
                # Optional: Print to console for immediate feedback
                if severity in ["HIGH", "CRITICAL", "EMERGENCY"]:
                    severity_emoji = "🚨" if severity == "CRITICAL" else "⚠️" if severity == "HIGH" else "🔺"
                    print(f"{severity_emoji} {anomaly_type}: {process_name} (PID {pid}) - {description}")
                
            except Exception as e:
                print(f"❌ Error logging anomaly: {e}")
    
    def log_process_burst(self, instigator_pid: str, instigator_name: str, 
                         num_processes: int, instigator_cmd: str = "", user: str = ""):
        """Log process burst anomaly"""
        self.log_anomaly(
            anomaly_type="PROCESS_BURST",
            process_name=instigator_name,
            pid=instigator_pid,
            description=f"Process burst: {num_processes} processes spawned rapidly",
            severity="HIGH" if num_processes > 15 else "MEDIUM",
            user=user,
            command=instigator_cmd,
            additional_info=f"burst_count:{num_processes}"
        )
    
    def log_cpu_anomaly(self, pid: str, process_name: str, cpu_usage: float, 
                       duration: str = "", command: str = "", user: str = ""):
        """Log CPU usage anomaly"""
        if cpu_usage > 95:
            severity = "CRITICAL"
            anomaly_type = "CRITICAL_CPU"
        elif cpu_usage > 80:
            severity = "HIGH" 
            anomaly_type = "HIGH_CPU"
        else:
            severity = "MEDIUM"
            anomaly_type = "HIGH_CPU"
            
        self.log_anomaly(
            anomaly_type=anomaly_type,
            process_name=process_name,
            pid=pid,
            description=f"High CPU usage: {cpu_usage:.1f}%",
            severity=severity,
            user=user,
            command=command,
            cpu_usage=cpu_usage,
            duration=duration
        )
    
    def log_memory_anomaly(self, pid: str, process_name: str, memory_mb: float,
                          command: str = "", user: str = ""):
        """Log memory usage anomaly"""
        if memory_mb > 1000:  # 1GB
            severity = "CRITICAL"
            anomaly_type = "CRITICAL_MEMORY"
        elif memory_mb > 500:  # 500MB
            severity = "HIGH"
            anomaly_type = "HIGH_MEMORY"
        else:
            severity = "MEDIUM"
            anomaly_type = "HIGH_MEMORY"
            
        self.log_anomaly(
            anomaly_type=anomaly_type,
            process_name=process_name,
            pid=pid,
            description=f"High memory usage: {memory_mb:.1f} MB",
            severity=severity,
            user=user,
            command=command,
            memory_usage_mb=memory_mb
        )
    
    def log_system_overload(self, cpu_usage: float, load_avg: str = ""):
        """Log system-wide overload"""
        self.log_anomaly(
            anomaly_type="SYSTEM_OVERLOAD",
            process_name="SYSTEM",
            description=f"System overload: {cpu_usage:.1f}% CPU, Load: {load_avg}",
            severity="CRITICAL" if cpu_usage > 95 else "HIGH",
            cpu_usage=cpu_usage,
            additional_info=f"load_average:{load_avg}"
        )
    
    def log_usb_event(self, device_name: str, action: str, vendor: str = ""):
        """Log USB device events"""
        self.log_anomaly(
            anomaly_type="USB_EVENT",
            process_name="USB_DEVICE",
            description=f"USB {action}: {vendor} {device_name}",
            severity="LOW" if action == "add" else "MEDIUM",
            additional_info=f"action:{action},vendor:{vendor}"
        )
    
    def log_new_process(self, pid: str, process_name: str, user: str, 
                       command: str, parent_pid: str = ""):
        """Log new process detection"""
        self.log_anomaly(
            anomaly_type="SUSPICIOUS_PROCESS",
            process_name=process_name,
            pid=pid,
            description=f"New process detected: {process_name}",
            severity="LOW",
            user=user,
            command=command,
            parent_pid=parent_pid
        )
    
    def get_anomaly_stats(self) -> Dict[str, Any]:
        """Get basic statistics about logged anomalies"""
        try:
            if not os.path.exists(self.csv_file):
                return {"error": "No anomaly data found"}
            
            stats = {
                "total_anomalies": 0,
                "by_type": {},
                "by_severity": {},
                "recent_count": 0  # Last hour
            }
            
            current_time = datetime.now(IST)
            one_hour_ago = current_time - timedelta(hours=1)
            
            with open(self.csv_file, "r", encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    stats["total_anomalies"] += 1
                    
                    # Count by type
                    anomaly_type = row.get("anomaly_type", "Unknown")
                    stats["by_type"][anomaly_type] = stats["by_type"].get(anomaly_type, 0) + 1
                    
                    # Count by severity
                    severity = row.get("severity", "Unknown")
                    stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
                    
                    # Count recent anomalies
                    try:
                        anomaly_time = datetime.strptime(row.get("timestamp", ""), '%Y-%m-%d %H:%M:%S')
                        if anomaly_time.replace(tzinfo=IST) > one_hour_ago:
                            stats["recent_count"] += 1
                    except:
                        pass
            
            return stats
            
        except Exception as e:
            return {"error": f"Error reading anomaly stats: {e}"}

# Global anomaly logger instance
anomaly_logger = AnomalyLogger()

# Convenience functions for easy integration with existing code
def log_anomaly(process_name: str, reason: str, pid: str = "", severity: str = "MEDIUM"):
    """Simple function to maintain compatibility with existing code"""
    anomaly_logger.log_anomaly(
        anomaly_type="SUSPICIOUS_PROCESS",
        process_name=process_name,
        pid=pid,
        description=reason,
        severity=severity
    )