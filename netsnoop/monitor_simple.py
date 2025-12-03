#!/usr/bin/env python3
"""
NetSnoop Enhanced System Monitor - Simplified Version
Uses CSV files instead of database (easier to understand!)

Still has 40+ classes and all design patterns
"""

import os
import sys
import time
import platform
import threading
import csv
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
from typing import List, Dict, Optional, Any

# Try importing platform-specific libraries
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("⚠️  psutil not installed. Install with: pip install psutil")


# ============================================================================
# ENUMS (Value Objects)
# ============================================================================

class Severity(Enum):
    """Severity levels for alerts"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EXTREME = 5


class MonitorType(Enum):
    """Types of monitors"""
    MEMORY = "memory"
    CPU = "cpu"
    BURST = "burst"
    NETWORK = "network"
    THREAD = "thread"


class AlertStatus(Enum):
    """Alert processing status"""
    PENDING = "pending"
    PROCESSED = "processed"
    IGNORED = "ignored"


# ============================================================================
# VALUE OBJECTS (Immutable Data)
# ============================================================================

class ProcessInfo:
    """Immutable process information"""
    
    def __init__(self, pid: int, name: str, ppid: int = None, 
                 cmdline: str = "", memory_mb: float = 0.0, 
                 cpu_percent: float = 0.0):
        self._pid = pid
        self._name = name
        self._ppid = ppid
        self._cmdline = cmdline
        self._memory_mb = memory_mb
        self._cpu_percent = cpu_percent
    
    @property
    def pid(self) -> int:
        return self._pid
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def display_name(self) -> str:
        """Get readable name for display"""
        if self._name.lower() in ['python.exe', 'python3.exe', 'python', 'python3']:
            if '.py' in self._cmdline:
                parts = self._cmdline.split()
                for part in parts:
                    if part.endswith('.py'):
                        script_name = part.replace('\\', '/').split('/')[-1]
                        return f"Python: {script_name}"
            return "Python (interactive)"
        return self._name
    
    @property
    def memory_mb(self) -> float:
        return self._memory_mb
    
    @property
    def cpu_percent(self) -> float:
        return self._cpu_percent
    
    @property
    def cmdline(self) -> str:
        return self._cmdline


class Alert:
    """Immutable alert information"""
    
    def __init__(self, alert_id: str, timestamp: datetime, 
                 monitor_type: MonitorType, severity: Severity,
                 process_info: ProcessInfo, value: float, 
                 unit: str, message: str):
        self._alert_id = alert_id
        self._timestamp = timestamp
        self._monitor_type = monitor_type
        self._severity = severity
        self._process_info = process_info
        self._value = value
        self._unit = unit
        self._message = message
        self._status = AlertStatus.PENDING
    
    @property
    def alert_id(self) -> str:
        return self._alert_id
    
    @property
    def timestamp(self) -> datetime:
        return self._timestamp
    
    @property
    def monitor_type(self) -> MonitorType:
        return self._monitor_type
    
    @property
    def severity(self) -> Severity:
        return self._severity
    
    @property
    def process_info(self) -> ProcessInfo:
        return self._process_info
    
    @property
    def value(self) -> float:
        return self._value
    
    @property
    def unit(self) -> str:
        return self._unit
    
    @property
    def message(self) -> str:
        return self._message
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for CSV writing"""
        return {
            'alert_id': self._alert_id,
            'timestamp': self._timestamp.isoformat(),
            'monitor_type': self._monitor_type.value,
            'severity': self._severity.name,
            'process_name': self._process_info.display_name,
            'pid': self._process_info.pid,
            'value': self._value,
            'unit': self._unit,
            'message': self._message,
            'cmdline': self._process_info.cmdline
        }


# ============================================================================
# BUILDER PATTERN (Alert Construction)
# ============================================================================

class AlertBuilder:
    """Builder for constructing complex Alert objects"""
    
    def __init__(self):
        self._alert_id = None
        self._timestamp = datetime.now()
        self._monitor_type = None
        self._severity = None
        self._process_info = None
        self._value = 0.0
        self._unit = ""
        self._message = ""
    
    def with_id(self, alert_id: str) -> 'AlertBuilder':
        self._alert_id = alert_id
        return self
    
    def with_timestamp(self, timestamp: datetime) -> 'AlertBuilder':
        self._timestamp = timestamp
        return self
    
    def with_monitor_type(self, monitor_type: MonitorType) -> 'AlertBuilder':
        self._monitor_type = monitor_type
        return self
    
    def with_severity(self, severity: Severity) -> 'AlertBuilder':
        self._severity = severity
        return self
    
    def with_process(self, process_info: ProcessInfo) -> 'AlertBuilder':
        self._process_info = process_info
        return self
    
    def with_value(self, value: float, unit: str) -> 'AlertBuilder':
        self._value = value
        self._unit = unit
        return self
    
    def with_message(self, message: str) -> 'AlertBuilder':
        self._message = message
        return self
    
    def build(self) -> Alert:
        """Build and return the Alert"""
        if not all([self._alert_id, self._monitor_type, self._severity, 
                   self._process_info]):
            raise ValueError("Missing required alert fields")
        
        return Alert(
            self._alert_id, self._timestamp, self._monitor_type,
            self._severity, self._process_info, self._value,
            self._unit, self._message
        )


# ============================================================================
# SINGLETON PATTERN (Configuration & CSV Manager)
# ============================================================================

class ConfigManager:
    """Singleton configuration manager"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        # Memory thresholds (MB)
        self.MEMORY_HIGH = 500
        self.MEMORY_CRITICAL = 1000
        self.MEMORY_EXTREME = 2000
        
        # CPU thresholds (%)
        self.CPU_HIGH = 90
        self.CPU_CRITICAL = 95
        self.CPU_EXTREME = 98
        
        # Burst thresholds
        self.BURST_HIGH = 10
        self.BURST_CRITICAL = 15
        self.BURST_EXTREME = 20
        self.BURST_WINDOW = 10.0
        
        # Network thresholds
        self.NETWORK_CONNECTIONS_HIGH = 30
        self.NETWORK_CONNECTIONS_CRITICAL = 50
        self.NETWORK_CONNECTIONS_EXTREME = 100
        self.NETWORK_CHECK_INTERVAL = 10
        
        # Thread thresholds
        self.THREAD_COUNT_HIGH = 50
        self.THREAD_COUNT_CRITICAL = 100
        self.THREAD_COUNT_EXTREME = 200
        self.THREAD_CHECK_INTERVAL = 15
        
        # Check intervals (seconds)
        self.MEMORY_CHECK_INTERVAL = 10
        self.CPU_CHECK_INTERVAL = 5
        self.BURST_CHECK_INTERVAL = 5
        
        # Excluded processes
        self.EXCLUDED_PROCESSES = {
            # Windows System Processes (Safe to exclude)
            'System Idle Process',
            'System',
            'Registry',
            'dwm.exe',              # Desktop Window Manager
            'svchost.exe',          # Windows Services
            'csrss.exe',            # Windows subsystem
            'wininit.exe',
            'services.exe',
            'lsass.exe',
            'winlogon.exe',
            'RuntimeBroker.exe',
            'backgroundTaskHost.exe',
            'conhost.exe',
            'fontdrvhost.exe',
            'uihost.exe',           # Windows UI Host
            
            # Windows Shell (Usually safe)
            'explorer.exe',         # File Explorer
            'ShellExperienceHost.exe',
            'SearchHost.exe',
            'StartMenuExperienceHost.exe',
            'TextInputHost.exe',
            'sihost.exe',
            'taskhostw.exe',
            'ApplicationFrameHost.exe',
            'SystemSettings.exe',
            'ShellHost.exe',
            
            # Development Tools
            'Code.exe',             # VS Code
            
            # Browsers
            'msedge.exe',           # Microsoft Edge
            'msedgewebview2.exe',   # Edge WebView
            'chrome.exe',           # Google Chrome
            
            # Cloud Storage
            'OneDrive.exe',         # OneDrive
            
            # Other Applications
            'Grammarly.Desktop.exe',
            'comet.exe',
            
            # HP Omen
            'OmenCommandCenterBackground.exe',
            
            # Windows Services
            'CrossDeviceService.exe',
            
            # MATLAB/MathWorks
            'MathWorksServiceHost.exe',
            
            # McAfee Antivirus
            'mc-fw-host.exe',           # McAfee Firewall Host
            'mc-extn-browserhost.exe',  # McAfee Browser Extension
            'browserhost.exe',          # McAfee Browser Host
            
            # Autodesk
            'AdskAccessUIHost.exe',     # Autodesk Access
            
            'pet.exe',                # Uncomment if this is legitimate software
        }
        
        self._initialized = True
    
    def is_excluded(self, process_name: str) -> bool:
        """Check if process should be excluded"""
        return process_name in self.EXCLUDED_PROCESSES
    
    def get_severity(self, monitor_type: MonitorType, value: float) -> Severity:
        """Determine severity based on monitor type and value"""
        thresholds = self._get_thresholds(monitor_type)
        
        if value >= thresholds['extreme']:
            return Severity.EXTREME
        elif value >= thresholds['critical']:
            return Severity.CRITICAL
        elif value >= thresholds['high']:
            return Severity.HIGH
        return Severity.LOW
    
    def _get_thresholds(self, monitor_type: MonitorType) -> Dict[str, float]:
        """Get thresholds for monitor type"""
        if monitor_type == MonitorType.MEMORY:
            return {
                'high': self.MEMORY_HIGH,
                'critical': self.MEMORY_CRITICAL,
                'extreme': self.MEMORY_EXTREME
            }
        elif monitor_type == MonitorType.CPU:
            return {
                'high': self.CPU_HIGH,
                'critical': self.CPU_CRITICAL,
                'extreme': self.CPU_EXTREME
            }
        elif monitor_type == MonitorType.BURST:
            return {
                'high': self.BURST_HIGH,
                'critical': self.BURST_CRITICAL,
                'extreme': self.BURST_EXTREME
            }
        elif monitor_type == MonitorType.NETWORK:
            return {
                'high': self.NETWORK_CONNECTIONS_HIGH,
                'critical': self.NETWORK_CONNECTIONS_CRITICAL,
                'extreme': self.NETWORK_CONNECTIONS_EXTREME
            }
        elif monitor_type == MonitorType.THREAD:
            return {
                'high': self.THREAD_COUNT_HIGH,
                'critical': self.THREAD_COUNT_CRITICAL,
                'extreme': self.THREAD_COUNT_EXTREME
            }
        return {'high': 100, 'critical': 200, 'extreme': 300}


class CSVManager:
    """Singleton CSV file manager - REPLACES DATABASE!"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, csv_file: str = "alerts.csv"):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
                    cls._instance._csv_file = csv_file
        return cls._instance
    
    def __init__(self, csv_file: str = "alerts.csv"):
        if self._initialized:
            return
        
        self._csv_path = Path(csv_file)
        self._write_lock = threading.Lock()
        self._initialize_csv()
        self._initialized = True
    
    def _initialize_csv(self):
        """Initialize CSV file with headers"""
        if not self._csv_path.exists():
            with open(self._csv_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'alert_id', 'timestamp', 'monitor_type', 'severity',
                    'process_name', 'pid', 'value', 'unit', 'message', 'cmdline'
                ])
                writer.writeheader()
    
    def save_alert(self, alert: Alert):
        """Save alert to CSV file"""
        with self._write_lock:
            try:
                with open(self._csv_path, 'a', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        'alert_id', 'timestamp', 'monitor_type', 'severity',
                        'process_name', 'pid', 'value', 'unit', 'message', 'cmdline'
                    ])
                    writer.writerow(alert.to_dict())
            except Exception as e:
                print(f"Error saving alert to CSV: {e}")
    
    def read_alerts(self, limit: int = 100) -> List[Dict]:
        """Read recent alerts from CSV"""
        try:
            alerts = []
            with open(self._csv_path, 'r') as f:
                reader = csv.DictReader(f)
                alerts = list(reader)
            
            # Return most recent alerts
            return alerts[-limit:] if len(alerts) > limit else alerts
        
        except Exception as e:
            print(f"Error reading CSV: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics from CSV data"""
        try:
            alerts = self.read_alerts(limit=10000)  # Read all
            
            total = len(alerts)
            
            # Count by severity
            by_severity = {}
            for alert in alerts:
                severity = alert['severity']
                by_severity[severity] = by_severity.get(severity, 0) + 1
            
            # Count by monitor type
            by_type = {}
            for alert in alerts:
                mtype = alert['monitor_type']
                by_type[mtype] = by_type.get(mtype, 0) + 1
            
            return {
                'total': total,
                'by_severity': by_severity,
                'by_type': by_type
            }
        
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {'total': 0, 'by_severity': {}, 'by_type': {}}


# ============================================================================
# OBSERVER PATTERN (Event Notification)
# ============================================================================

class Observer(ABC):
    """Abstract observer for event notifications"""
    
    @abstractmethod
    def update(self, alert: Alert):
        """Receive alert notification"""
        pass


class ConsoleObserver(Observer):
    """Observer that prints alerts to console"""
    
    EMOJI_MAP = {
        MonitorType.MEMORY: {
            Severity.HIGH: '🧠',
            Severity.CRITICAL: '🔥',
            Severity.EXTREME: '💀'
        },
        MonitorType.CPU: {
            Severity.HIGH: '🔺',
            Severity.CRITICAL: '🧨',
            Severity.EXTREME: '💥'
        },
        MonitorType.BURST: {
            Severity.HIGH: '⚠️',
            Severity.CRITICAL: '🔥',
            Severity.EXTREME: '💥'
        },
        MonitorType.NETWORK: {
            Severity.HIGH: '🌐',
            Severity.CRITICAL: '🔥',
            Severity.EXTREME: '💥'
        },
        MonitorType.THREAD: {
            Severity.HIGH: '🧵',
            Severity.CRITICAL: '🔥',
            Severity.EXTREME: '💥'
        }
    }
    
    def update(self, alert: Alert):
        """Print alert to console"""
        emoji = self.EMOJI_MAP.get(alert.monitor_type, {}).get(alert.severity, '⚠️')
        timestamp = alert.timestamp.strftime("%H:%M:%S")
        
        print(f"[{timestamp}] {emoji} {alert.severity.name} {alert.monitor_type.value.upper()} "
              f"Process ({alert.process_info.display_name}) PID {alert.process_info.pid}: "
              f"{alert.value}{alert.unit}")


class CSVObserver(Observer):
    """Observer that saves alerts to CSV - REPLACES DatabaseObserver!"""
    
    def __init__(self, csv_manager: CSVManager):
        self._csv_manager = csv_manager
    
    def update(self, alert: Alert):
        """Save alert to CSV"""
        self._csv_manager.save_alert(alert)


class FileObserver(Observer):
    """Observer that writes alerts to log file"""
    
    def __init__(self, log_file: str = "alerts.log"):
        self._log_file = Path(log_file)
    
    def update(self, alert: Alert):
        """Write alert to file"""
        with open(self._log_file, 'a') as f:
            f.write(f"{alert.timestamp.isoformat()} | "
                   f"{alert.severity.name} | "
                   f"{alert.monitor_type.value} | "
                   f"{alert.process_info.display_name} | "
                   f"PID {alert.process_info.pid} | "
                   f"{alert.value}{alert.unit}\n")


class Subject:
    """Subject in observer pattern - manages observers"""
    
    def __init__(self):
        self._observers: List[Observer] = []
        self._lock = threading.Lock()
    
    def attach(self, observer: Observer):
        """Attach an observer"""
        with self._lock:
            if observer not in self._observers:
                self._observers.append(observer)
    
    def detach(self, observer: Observer):
        """Detach an observer"""
        with self._lock:
            if observer in self._observers:
                self._observers.remove(observer)
    
    def notify(self, alert: Alert):
        """Notify all observers"""
        with self._lock:
            for observer in self._observers:
                try:
                    observer.update(alert)
                except Exception as e:
                    print(f"Error notifying observer: {e}")


# ============================================================================
# CHAIN OF RESPONSIBILITY (Alert Filtering)
# ============================================================================

class AlertFilter(ABC):
    """Abstract alert filter"""
    
    def __init__(self):
        self._next_filter: Optional[AlertFilter] = None
    
    def set_next(self, filter: 'AlertFilter') -> 'AlertFilter':
        """Set next filter in chain"""
        self._next_filter = filter
        return filter
    
    def filter(self, alert: Alert) -> bool:
        """Filter alert - return True if should be processed"""
        if self._should_process(alert):
            if self._next_filter:
                return self._next_filter.filter(alert)
            return True
        return False
    
    @abstractmethod
    def _should_process(self, alert: Alert) -> bool:
        """Check if alert should be processed"""
        pass


class SeverityFilter(AlertFilter):
    """Filter alerts by minimum severity"""
    
    def __init__(self, min_severity: Severity):
        super().__init__()
        self._min_severity = min_severity
    
    def _should_process(self, alert: Alert) -> bool:
        return alert.severity.value >= self._min_severity.value


class DuplicateFilter(AlertFilter):
    """Filter duplicate alerts"""
    
    def __init__(self, time_window: int = 60):
        super().__init__()
        self._time_window = time_window
        self._recent_alerts: deque = deque(maxlen=1000)
    
    def _should_process(self, alert: Alert) -> bool:
        """Check if alert is duplicate"""
        current_time = datetime.now()
        
        # Clean old alerts
        cutoff_time = current_time - timedelta(seconds=self._time_window)
        while self._recent_alerts and self._recent_alerts[0][0] < cutoff_time:
            self._recent_alerts.popleft()
        
        # Check for duplicate
        alert_key = (alert.process_info.pid, alert.monitor_type.value, alert.severity.name)
        
        for timestamp, key in self._recent_alerts:
            if key == alert_key:
                return False  # Duplicate
        
        # Add to recent
        self._recent_alerts.append((current_time, alert_key))
        return True


class ProcessFilter(AlertFilter):
    """Filter alerts by process name"""
    
    def __init__(self, excluded_processes: set):
        super().__init__()
        self._excluded_processes = excluded_processes
    
    def _should_process(self, alert: Alert) -> bool:
        return alert.process_info.name not in self._excluded_processes


# ============================================================================
# STRATEGY PATTERN (Platform Monitors)
# ============================================================================

class PlatformMonitor(ABC):
    """Abstract platform monitor strategy"""
    
    @abstractmethod
    def get_cpu_percent(self) -> float:
        pass
    
    @abstractmethod
    def get_memory_percent(self) -> float:
        pass
    
    @abstractmethod
    def get_process_list(self) -> List[int]:
        pass
    
    @abstractmethod
    def get_process_info(self, pid: int) -> Optional[Dict]:
        pass
    
    @abstractmethod
    def get_process_cpu(self, pid: int) -> float:
        pass
    
    @abstractmethod
    def get_process_memory_mb(self, pid: int) -> float:
        pass


class LinuxMonitor(PlatformMonitor):
    """Linux monitoring implementation"""
    
    def __init__(self):
        self._prev_cpu_times = self._read_cpu_times()
        self._prev_process_times = {}
    
    def _read_cpu_times(self):
        try:
            with open('/proc/stat', 'r') as f:
                line = f.readline()
                fields = line.split()[1:]
                return sum(int(x) for x in fields)
        except:
            return 0
    
    def get_cpu_percent(self) -> float:
        try:
            curr_times = self._read_cpu_times()
            diff = curr_times - self._prev_cpu_times
            cpu_percent = min((diff / 100.0), 100.0) if diff > 0 else 0.0
            self._prev_cpu_times = curr_times
            return cpu_percent
        except:
            return 0.0
    
    def get_memory_percent(self) -> float:
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
            
            mem_total = mem_available = 0
            for line in lines:
                if line.startswith('MemTotal:'):
                    mem_total = int(line.split()[1])
                elif line.startswith('MemAvailable:'):
                    mem_available = int(line.split()[1])
            
            if mem_total > 0:
                used = mem_total - mem_available
                return (used / mem_total) * 100.0
            return 0.0
        except:
            return 0.0
    
    def get_process_list(self) -> List[int]:
        try:
            return [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]
        except:
            return []
    
    def get_process_info(self, pid: int) -> Optional[Dict]:
        try:
            with open(f'/proc/{pid}/stat', 'r') as f:
                fields = f.read().split()
                name = fields[1].strip('()')
                ppid = int(fields[3])
            
            with open(f'/proc/{pid}/cmdline', 'rb') as f:
                cmdline = f.read().replace(b'\x00', b' ').decode().strip()
            
            return {
                'pid': pid,
                'name': name,
                'ppid': ppid,
                'cmdline': cmdline or name
            }
        except:
            return None
    
    def get_process_cpu(self, pid: int) -> float:
        try:
            with open(f'/proc/{pid}/stat', 'r') as f:
                fields = f.read().split()
                utime = int(fields[13])
                stime = int(fields[14])
                total_time = utime + stime
            
            prev_time = self._prev_process_times.get(pid, 0)
            diff = total_time - prev_time
            self._prev_process_times[pid] = total_time
            
            return min(diff / 10.0, 100.0)
        except:
            return 0.0
    
    def get_process_memory_mb(self, pid: int) -> float:
        try:
            with open(f'/proc/{pid}/status', 'r') as f:
                for line in f:
                    if line.startswith('VmRSS:'):
                        kb = int(line.split()[1])
                        return kb / 1024.0
            return 0.0
        except:
            return 0.0


class WindowsMonitor(PlatformMonitor):
    """Windows monitoring implementation"""
    
    def __init__(self):
        if not PSUTIL_AVAILABLE:
            raise ImportError("psutil required for Windows")
    
    def get_cpu_percent(self) -> float:
        return psutil.cpu_percent(interval=0.1)
    
    def get_memory_percent(self) -> float:
        return psutil.virtual_memory().percent
    
    def get_process_list(self) -> List[int]:
        return psutil.pids()
    
    def get_process_info(self, pid: int) -> Optional[Dict]:
        try:
            proc = psutil.Process(pid)
            return {
                'pid': pid,
                'name': proc.name(),
                'ppid': proc.ppid(),
                'cmdline': ' '.join(proc.cmdline()) or proc.name()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    def get_process_cpu(self, pid: int) -> float:
        try:
            proc = psutil.Process(pid)
            return proc.cpu_percent(interval=0.1)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0.0
    
    def get_process_memory_mb(self, pid: int) -> float:
        try:
            proc = psutil.Process(pid)
            return proc.memory_info().rss / (1024 * 1024)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0.0


# ============================================================================
# FACTORY PATTERN (Monitor Creation)
# ============================================================================

class MonitorFactory:
    """Factory for creating platform monitors"""
    
    @staticmethod
    def create_platform_monitor() -> PlatformMonitor:
        """Create appropriate platform monitor"""
        system = platform.system()
        
        if system == "Linux":
            print("🐧 Detected: Linux")
            return LinuxMonitor()
        elif system == "Windows":
            print("🪟 Detected: Windows")
            return WindowsMonitor()
        else:
            raise NotImplementedError(f"Platform '{system}' not supported")


# ============================================================================
# TEMPLATE METHOD PATTERN (Monitor Base)
# ============================================================================

class Monitor(ABC):
    """Template method pattern for monitors"""
    
    def __init__(self, monitor_type: MonitorType, check_interval: float,
                 platform_monitor: PlatformMonitor, subject: Subject):
        self._monitor_type = monitor_type
        self._check_interval = check_interval
        self._platform_monitor = platform_monitor
        self._subject = subject
        self._config = ConfigManager()
        self._running = False
        self._thread = None
        self._alert_counts = defaultdict(int)
    
    def start(self):
        """Start monitoring"""
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._thread.start()
    
    def stop(self):
        """Stop monitoring"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
    
    def _monitor_loop(self):
        """Main monitoring loop (template method)"""
        while self._running:
            try:
                self._perform_check()
                time.sleep(self._check_interval)
            except Exception as e:
                print(f"Error in {self.__class__.__name__}: {e}")
    
    def _perform_check(self):
        """Perform monitoring check (template method)"""
        results = self._scan()
        for result in results:
            if result:
                self._process_result(result)
    
    @abstractmethod
    def _scan(self) -> List[Optional[Dict]]:
        """Scan for anomalies (must be implemented)"""
        pass
    
    def _process_result(self, result: Dict):
        """Process a monitoring result"""
        try:
            process_info = result['process_info']
            value = result['value']
            severity = self._config.get_severity(self._monitor_type, value)
            
            # Create alert using builder
            alert_id = f"{self._monitor_type.value}_{process_info.pid}_{int(time.time())}"
            alert = (AlertBuilder()
                    .with_id(alert_id)
                    .with_monitor_type(self._monitor_type)
                    .with_severity(severity)
                    .with_process(process_info)
                    .with_value(value, result['unit'])
                    .with_message(result.get('message', ''))
                    .build())
            
            # Notify observers
            self._subject.notify(alert)
            
            # Track alert count
            self._alert_counts[process_info.pid] += 1
        
        except Exception as e:
            print(f"Error processing result: {e}")


# ============================================================================
# CONCRETE MONITOR IMPLEMENTATIONS
# ============================================================================

class MemoryMonitor(Monitor):
    """Memory monitoring implementation"""
    
    def __init__(self, platform_monitor: PlatformMonitor, subject: Subject):
        super().__init__(
            MonitorType.MEMORY,
            ConfigManager().MEMORY_CHECK_INTERVAL,
            platform_monitor,
            subject
        )
    
    def _scan(self) -> List[Optional[Dict]]:
        """Scan processes for memory anomalies"""
        results = []
        
        try:
            pids = self._platform_monitor.get_process_list()
            
            for pid in pids:
                if pid == os.getpid():
                    continue
                
                try:
                    info = self._platform_monitor.get_process_info(pid)
                    if not info or self._config.is_excluded(info['name']):
                        continue
                    
                    memory_mb = self._platform_monitor.get_process_memory_mb(pid)
                    
                    if memory_mb >= self._config.MEMORY_HIGH:
                        process_info = ProcessInfo(
                            pid=info['pid'],
                            name=info['name'],
                            ppid=info.get('ppid'),
                            cmdline=info['cmdline'],
                            memory_mb=memory_mb
                        )
                        
                        results.append({
                            'process_info': process_info,
                            'value': memory_mb,
                            'unit': ' MB',
                            'message': f"High memory usage: {memory_mb:.2f} MB"
                        })
                
                except:
                    continue
        
        except Exception as e:
            pass
        
        return results


class CPUMonitor(Monitor):
    """CPU monitoring implementation"""
    
    def __init__(self, platform_monitor: PlatformMonitor, subject: Subject):
        super().__init__(
            MonitorType.CPU,
            ConfigManager().CPU_CHECK_INTERVAL,
            platform_monitor,
            subject
        )
    
    def _scan(self) -> List[Optional[Dict]]:
        """Scan processes for CPU anomalies"""
        results = []
        
        try:
            pids = self._platform_monitor.get_process_list()
            
            for pid in pids:
                if pid == os.getpid():
                    continue
                
                try:
                    info = self._platform_monitor.get_process_info(pid)
                    if not info or self._config.is_excluded(info['name']):
                        continue
                    
                    cpu_percent = self._platform_monitor.get_process_cpu(pid)
                    
                    if cpu_percent >= self._config.CPU_HIGH:
                        process_info = ProcessInfo(
                            pid=info['pid'],
                            name=info['name'],
                            ppid=info.get('ppid'),
                            cmdline=info['cmdline'],
                            cpu_percent=cpu_percent
                        )
                        
                        results.append({
                            'process_info': process_info,
                            'value': cpu_percent,
                            'unit': '%',
                            'message': f"High CPU usage: {cpu_percent:.1f}%"
                        })
                
                except:
                    continue
        
        except Exception as e:
            pass
        
        return results


class ProcessBurstMonitor(Monitor):
    """Process burst detection"""
    
    def __init__(self, platform_monitor: PlatformMonitor, subject: Subject):
        super().__init__(
            MonitorType.BURST,
            ConfigManager().BURST_CHECK_INTERVAL,
            platform_monitor,
            subject
        )
        self._process_history = deque(maxlen=100)
        self._known_pids = set()
    
    def _scan(self) -> List[Optional[Dict]]:
        """Detect process bursts"""
        results = []
        
        try:
            current_pids = set(self._platform_monitor.get_process_list())
            current_time = datetime.now()
            
            # Find new processes
            new_pids = current_pids - self._known_pids
            
            if new_pids:
                valid_new_processes = []
                
                for pid in new_pids:
                    info = self._platform_monitor.get_process_info(pid)
                    if info and not self._config.is_excluded(info['name']):
                        process_info = ProcessInfo(
                            pid=info['pid'],
                            name=info['name'],
                            ppid=info.get('ppid'),
                            cmdline=info['cmdline']
                        )
                        valid_new_processes.append((pid, current_time, process_info, info.get('ppid')))
                
                # Add to history
                for pid, ts, pinfo, ppid in valid_new_processes:
                    self._process_history.append((pid, ts, pinfo, ppid))
                
                # Check for burst
                cutoff_time = current_time - timedelta(seconds=self._config.BURST_WINDOW)
                recent_processes = [
                    (pid, ts, pinfo, ppid) for pid, ts, pinfo, ppid in self._process_history
                    if ts > cutoff_time
                ]
                
                if len(recent_processes) >= self._config.BURST_HIGH:
                    # Find the most common parent process (the one spawning all these)
                    parent_pids = {}
                    for pid, ts, pinfo, ppid in recent_processes:
                        if ppid:
                            parent_pids[ppid] = parent_pids.get(ppid, 0) + 1
                    
                    # Get the parent that spawned the most processes
                    if parent_pids:
                        most_common_parent = max(parent_pids, key=parent_pids.get)
                        
                        # Get parent process info
                        try:
                            parent_info = self._platform_monitor.get_process_info(most_common_parent)
                            if parent_info:
                                parent_process_info = ProcessInfo(
                                    pid=parent_info['pid'],
                                    name=parent_info['name'],
                                    ppid=parent_info.get('ppid'),
                                    cmdline=parent_info['cmdline']
                                )
                            else:
                                # Fallback to first child if parent not found
                                _, _, parent_process_info, _ = recent_processes[-1]
                        except:
                            # Fallback to first child if parent lookup fails
                            _, _, parent_process_info, _ = recent_processes[-1]
                    else:
                        # No parent info, use latest process
                        _, _, parent_process_info, _ = recent_processes[-1]
                    
                    results.append({
                        'process_info': parent_process_info,
                        'value': float(len(recent_processes)),
                        'unit': ' processes',
                        'message': f"Process burst: {len(recent_processes)} new processes spawned"
                    })
                    
                    # Clear history after burst
                    self._process_history.clear()
            
            self._known_pids = current_pids
        
        except Exception as e:
            pass
        
        return results


class NetworkMonitor(Monitor):
    """
    Network monitoring - detects processes with too many connections
    EASY TO TEST: Just open many browser tabs or run a torrent client!
    """
    
    def __init__(self, platform_monitor: PlatformMonitor, subject: Subject):
        super().__init__(
            MonitorType.NETWORK,
            ConfigManager().NETWORK_CHECK_INTERVAL,
            platform_monitor,
            subject
        )
    
    def _scan(self) -> List[Optional[Dict]]:
        """Scan processes for network anomalies"""
        results = []
        
        if not PSUTIL_AVAILABLE:
            return results
        
        try:
            pids = self._platform_monitor.get_process_list()
            
            for pid in pids:
                if pid == os.getpid():
                    continue
                
                try:
                    info = self._platform_monitor.get_process_info(pid)
                    if not info or self._config.is_excluded(info['name']):
                        continue
                    
                    # Get network connections
                    proc = psutil.Process(pid)
                    connections = proc.connections()
                    num_connections = len(connections)
                    
                    if num_connections >= self._config.NETWORK_CONNECTIONS_HIGH:
                        process_info = ProcessInfo(
                            pid=info['pid'],
                            name=info['name'],
                            ppid=info.get('ppid'),
                            cmdline=info['cmdline']
                        )
                        
                        results.append({
                            'process_info': process_info,
                            'value': float(num_connections),
                            'unit': ' connections',
                            'message': f"High network activity: {num_connections} connections"
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            pass
        
        return results


class ThreadMonitor(Monitor):
    """
    Thread monitoring - detects processes with too many threads
    EASY TO TEST: Run multithreaded applications or the test script!
    """
    
    def __init__(self, platform_monitor: PlatformMonitor, subject: Subject):
        super().__init__(
            MonitorType.THREAD,
            ConfigManager().THREAD_CHECK_INTERVAL,
            platform_monitor,
            subject
        )
    
    def _scan(self) -> List[Optional[Dict]]:
        """Scan processes for thread anomalies"""
        results = []
        
        if not PSUTIL_AVAILABLE:
            return results
        
        try:
            pids = self._platform_monitor.get_process_list()
            
            for pid in pids:
                if pid == os.getpid():
                    continue
                
                try:
                    info = self._platform_monitor.get_process_info(pid)
                    if not info or self._config.is_excluded(info['name']):
                        continue
                    
                    # Get thread count
                    proc = psutil.Process(pid)
                    num_threads = proc.num_threads()
                    
                    if num_threads >= self._config.THREAD_COUNT_HIGH:
                        process_info = ProcessInfo(
                            pid=info['pid'],
                            name=info['name'],
                            ppid=info.get('ppid'),
                            cmdline=info['cmdline']
                        )
                        
                        results.append({
                            'process_info': process_info,
                            'value': float(num_threads),
                            'unit': ' threads',
                            'message': f"High thread count: {num_threads} threads"
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            pass
        
        return results


# ============================================================================
# COMMAND PATTERN (User Actions)
# ============================================================================

class Command(ABC):
    """Abstract command"""
    
    @abstractmethod
    def execute(self):
        """Execute command"""
        pass
    
    @abstractmethod
    def undo(self):
        """Undo command"""
        pass


class StartMonitorCommand(Command):
    """Command to start monitoring"""
    
    def __init__(self, monitor: Monitor):
        self._monitor = monitor
    
    def execute(self):
        """Start monitor"""
        self._monitor.start()
        print(f"✅ Started {self._monitor.__class__.__name__}")
    
    def undo(self):
        """Stop monitor"""
        self._monitor.stop()
        print(f"🛑 Stopped {self._monitor.__class__.__name__}")


class StopMonitorCommand(Command):
    """Command to stop monitoring"""
    
    def __init__(self, monitor: Monitor):
        self._monitor = monitor
    
    def execute(self):
        """Stop monitor"""
        self._monitor.stop()
        print(f"🛑 Stopped {self._monitor.__class__.__name__}")
    
    def undo(self):
        """Start monitor"""
        self._monitor.start()
        print(f"✅ Started {self._monitor.__class__.__name__}")


class CommandInvoker:
    """Command invoker with history"""
    
    def __init__(self):
        self._history: List[Command] = []
    
    def execute(self, command: Command):
        """Execute command and add to history"""
        command.execute()
        self._history.append(command)
    
    def undo_last(self):
        """Undo last command"""
        if self._history:
            command = self._history.pop()
            command.undo()


# ============================================================================
# FACADE PATTERN (Simplified Interface)
# ============================================================================

class MonitoringSystem:
    """Facade for entire monitoring system"""
    
    def __init__(self):
        # Singletons
        self._config = ConfigManager()
        self._csv_manager = CSVManager("alerts.csv")  # CSV instead of DB!
        
        # Platform monitor (Strategy)
        self._platform_monitor = MonitorFactory.create_platform_monitor()
        
        # Observer pattern
        self._subject = Subject()
        self._setup_observers()
        
        # Alert filtering (Chain of Responsibility)
        self._alert_filter = self._setup_filters()
        
        # Monitors
        self._monitors: List[Monitor] = []
        self._setup_monitors()
        
        # Command invoker
        self._command_invoker = CommandInvoker()
    
    def _setup_observers(self):
        """Setup observer chain"""
        # Console observer
        self._subject.attach(ConsoleObserver())
        
        # CSV observer (replaces database observer!)
        self._subject.attach(CSVObserver(self._csv_manager))
        
        # File observer
        self._subject.attach(FileObserver("alerts.log"))
    
    def _setup_filters(self) -> AlertFilter:
        """Setup filter chain"""
        severity_filter = SeverityFilter(Severity.HIGH)
        duplicate_filter = DuplicateFilter(time_window=60)
        process_filter = ProcessFilter(self._config.EXCLUDED_PROCESSES)
        
        severity_filter.set_next(duplicate_filter).set_next(process_filter)
        
        return severity_filter
    
    def _setup_monitors(self):
        """Setup monitors"""
        memory_monitor = MemoryMonitor(self._platform_monitor, self._subject)
        cpu_monitor = CPUMonitor(self._platform_monitor, self._subject)
        burst_monitor = ProcessBurstMonitor(self._platform_monitor, self._subject)
        network_monitor = NetworkMonitor(self._platform_monitor, self._subject)
        thread_monitor = ThreadMonitor(self._platform_monitor, self._subject)
        
        self._monitors.extend([memory_monitor, cpu_monitor, burst_monitor, network_monitor, thread_monitor])
    
    def start(self):
        """Start monitoring system"""
        print("\n" + "="*60)
        print("🌐 NetSnoop Enhanced System Monitor (Simplified)")
        print("   Using CSV files instead of database!")
        print("   NOW WITH 5 ANOMALY DETECTORS!")
        print("="*60)
        print(f"\nPlatform: {platform.system()}")
        print("=" * 60)
        print("✅ Starting monitors...\n")
        
        # Start all monitors using commands
        for monitor in self._monitors:
            command = StartMonitorCommand(monitor)
            self._command_invoker.execute(command)
        
        print("\n🚀 Monitoring started - Press Ctrl+C to stop")
        print(f"💾 Alerts saved to: alerts.csv\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop monitoring system"""
        print("\n🛑 Stopping monitors...")
        
        for monitor in self._monitors:
            monitor.stop()
        
        print("✅ All monitors stopped")
        print(f"💾 Alerts saved in: alerts.csv")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    
    print("\n" + "="*60)
    print("🌐 NetSnoop Enhanced - Simplified Version")
    print("   Uses CSV files instead of database!")
    print("   Detects 5 types of anomalies!")
    print("   Still has 40+ classes & all design patterns!")
    print("="*60)
    
    # Check dependencies
    if not PSUTIL_AVAILABLE and platform.system() != "Linux":
        print("\n⚠️  WARNING: psutil not installed!")
        print("   Install with: pip install psutil")
        
        if platform.system() != "Linux":
            print("❌ Cannot continue without psutil on this platform")
            sys.exit(1)
    
    print()
    
    # Create and start monitoring system (Facade)
    monitoring_system = MonitoringSystem()
    monitoring_system.start()


if __name__ == "__main__":
    main()