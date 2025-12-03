# 🌐 NetSnoop Enhanced System Monitor

A comprehensive, production-grade system monitoring application with real-time anomaly detection and professional dashboard visualization.

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

---

## 🎯 Overview

NetSnoop is an advanced system monitoring tool that detects 5 types of anomalies in real-time:

- 🧠 **Memory Anomalies** - Detect memory leaks and excessive RAM usage
- 🔺 **CPU Anomalies** - Identify CPU-intensive processes and infinite loops
- ⚠️ **Process Burst Anomalies** - Catch malware, ransomware, and fork bombs (Security)
- 🌐 **Network Anomalies** - Detect data exfiltration and botnet activity (Security)
- 🧵 **Thread Anomalies** - Find thread leaks and poorly designed applications

**Key Features:**
- 42+ classes demonstrating comprehensive OOP design
- 10+ design patterns (Observer, Strategy, Singleton, Factory, Builder, Template Method, Chain of Responsibility, Command, Facade, Repository)
- Cross-platform support (Windows & Linux)
- CSV-based storage (no database required)
- Professional Streamlit dashboard
- Real-time monitoring with configurable thresholds
- Parent process tracking for burst detection

---

## 🚀 Quick Start

### Installation

```bash
# Install dependencies
pip install psutil streamlit plotly pandas

# Clone the repository
git clone https://github.com/yourusername/netsnoop-monitor.git
cd netsnoop-monitor
```

### Run the Monitor

```bash
# Start monitoring in background
python simple_monitor.py
```

### Open the Dashboard

```bash
# Launch the web dashboard (opens at http://localhost:8501)
streamlit run simple_dashboard.py
```

### Test Anomaly Detection

```bash
# Test memory anomaly (allocates 600 MB)
python test_memory.py

# Test CPU anomaly (runs infinite loop)
python test_cpu.py

# Test burst anomaly (spawns 15 processes)
python test_burst.py

# Test network anomaly (opens 35 connections)
python test_network.py

# Test thread anomaly (creates 60 threads)
python test_thread.py
```

---

## 📊 Screenshots

### Dashboard Overview
The dashboard provides real-time visualization of all system anomalies with interactive charts and detailed alert tables.

### Console Monitoring
```
====================================================================
🌐 NetSnoop Enhanced System Monitor
   NOW WITH 5 ANOMALY DETECTORS!
====================================================================
✅ Started MemoryMonitor
✅ Started CPUMonitor
✅ Started ProcessBurstMonitor
✅ Started NetworkMonitor
✅ Started ThreadMonitor

[19:00:00] 🧠 CRITICAL MEMORY Process (Python: test_memory.py) PID 1234: 1209.8 MB
[19:01:00] 🔺 HIGH CPU Process (Python: test_cpu.py) PID 5678: 95.2%
[19:02:00] 🔥 CRITICAL BURST Process (Python: test_burst.py) PID 9012: 15.0 processes
```

---

## 🏗️ Architecture

### System Layers

```
┌─────────────────────────────────────┐
│     PRESENTATION LAYER              │
│  (Streamlit Dashboard)              │
└─────────────────────────────────────┘
              ↕
┌─────────────────────────────────────┐
│   DATA PERSISTENCE LAYER            │
│  (CSV File Manager)                 │
└─────────────────────────────────────┘
              ↕
┌─────────────────────────────────────┐
│   MONITORING ENGINE LAYER           │
│  (5 Specialized Monitors)           │
└─────────────────────────────────────┘
              ↕
┌─────────────────────────────────────┐
│  PLATFORM ABSTRACTION LAYER         │
│  (Windows/Linux Implementations)    │
└─────────────────────────────────────┘
```

### Design Patterns

NetSnoop implements 10+ design patterns:

| Pattern | Usage | Benefit |
|---------|-------|---------|
| **Singleton** | ConfigManager, CSVManager | Single source of truth |
| **Factory** | MonitorFactory | Platform-specific creation |
| **Observer** | Alert notifications | Loose coupling, multi-channel alerts |
| **Strategy** | PlatformMonitor | Cross-platform compatibility |
| **Builder** | AlertBuilder | Fluent alert construction |
| **Template Method** | Monitor base class | Code reuse, consistent structure |
| **Chain of Responsibility** | AlertFilter | Flexible filtering pipeline |
| **Command** | Monitor control | Undo/redo support |
| **Facade** | MonitoringSystem | Simplified interface |
| **Repository** | Data access | Storage abstraction |

---

## 🔍 Anomaly Detection

### 1. Memory Monitoring 🧠

**What it detects:** Processes using excessive memory

**Thresholds:**
- HIGH: ≥ 500 MB
- CRITICAL: ≥ 1000 MB
- EXTREME: ≥ 2000 MB

**Use cases:**
- Memory leaks detection
- Resource-hungry applications
- System crash prevention

**Test:** `python test_memory.py` (allocates 600 MB)

---

### 2. CPU Monitoring 🔺

**What it detects:** Processes consuming excessive CPU

**Thresholds:**
- HIGH: ≥ 90%
- CRITICAL: ≥ 95%
- EXTREME: ≥ 98%

**Use cases:**
- Infinite loop detection
- Performance optimization
- Runaway process identification

**Test:** `python test_cpu.py` (runs infinite loop)

---

### 3. Process Burst Detection ⚠️ (Security)

**What it detects:** Sudden mass process creation

**Thresholds:**
- HIGH: ≥ 10 processes in 10 seconds
- CRITICAL: ≥ 15 processes in 10 seconds
- EXTREME: ≥ 20 processes in 10 seconds

**Use cases:**
- Malware detection
- Ransomware detection
- Fork bomb prevention

**Special feature:** Shows parent process that spawned the burst!

**Test:** `python test_burst.py` (spawns 15 processes)

---

### 4. Network Monitoring 🌐 (Security)

**What it detects:** Processes with excessive network connections

**Thresholds:**
- HIGH: ≥ 30 connections
- CRITICAL: ≥ 50 connections
- EXTREME: ≥ 100 connections

**Use cases:**
- Data exfiltration detection
- Botnet activity detection
- Unusual network behavior

**Test:** `python test_network.py` (opens 35 connections)

---

### 5. Thread Monitoring 🧵

**What it detects:** Processes with excessive threads

**Thresholds:**
- HIGH: ≥ 50 threads
- CRITICAL: ≥ 100 threads
- EXTREME: ≥ 200 threads

**Use cases:**
- Thread leak detection
- Poorly designed application identification
- System instability prevention

**Test:** `python test_thread.py` (creates 60 threads)

---

## 📁 Project Structure

```
netsnoop-monitor/
├── simple_monitor.py          # Main monitoring engine (47KB, 42+ classes)
├── simple_dashboard.py        # Streamlit dashboard (19KB)
├── requirements.txt           # Python dependencies
├── README.md                  # This file
│
├── Test Scripts/
│   ├── test_memory.py         # Memory anomaly test
│   ├── test_cpu.py            # CPU anomaly test
│   ├── test_burst.py          # Burst anomaly test
│   ├── test_network.py        # Network anomaly test
│   └── test_thread.py         # Thread anomaly test
│
├── Generated Files/
│   ├── alerts.csv             # Alert storage (CSV format)
│   └── alerts.log             # Alert logging
│
└── Documentation/
    ├── CODE_SUMMARY.md        # Complete code explanation
    ├── COMPLETE_UML_DIAGRAMS.md  # UML diagrams
    ├── FINAL_PROJECT_REPORT.md   # Academic report
    └── ... (15+ more guides)
```

---

## 🎨 Dashboard Features

### Real-time Metrics
- Total alerts count
- Alert severity distribution
- Most affected processes
- Alert trends over time

### Interactive Visualizations
- **Timeline Chart** - Alert distribution over time
- **Severity Pie Chart** - Alert severity breakdown
- **Monitor Type Bar Chart** - Alerts by monitor type
- **Alert Table** - Detailed alert information with filters

### Filters & Controls
- Filter by severity (HIGH, CRITICAL, EXTREME)
- Filter by monitor type
- Auto-refresh interval (10-60 seconds)
- Search by process name

---

## ⚙️ Configuration

### Customizable Thresholds

Edit `ConfigManager` class in `simple_monitor.py`:

```python
# Memory thresholds (MB)
MEMORY_HIGH = 500
MEMORY_CRITICAL = 1000
MEMORY_EXTREME = 2000

# CPU thresholds (%)
CPU_HIGH = 90
CPU_CRITICAL = 95
CPU_EXTREME = 98

# Process burst thresholds (processes in 10s window)
BURST_HIGH = 10
BURST_CRITICAL = 15
BURST_EXTREME = 20

# Network thresholds (connections)
NETWORK_CONNECTIONS_HIGH = 30
NETWORK_CONNECTIONS_CRITICAL = 50
NETWORK_CONNECTIONS_EXTREME = 100

# Thread thresholds (threads)
THREAD_COUNT_HIGH = 50
THREAD_COUNT_CRITICAL = 100
THREAD_COUNT_EXTREME = 200
```

### Excluded Processes

By default, 50 system processes are excluded to reduce noise:
- Windows system processes (dwm.exe, svchost.exe, etc.)
- Browsers (Chrome, Edge)
- Development tools (VS Code)
- Antivirus software (McAfee, Windows Defender)
- And more...

To customize, edit the `EXCLUDED_PROCESSES` set in `ConfigManager`.

---

## 🔧 Advanced Usage

### Import as Library

```python
from simple_monitor import MonitoringSystem, ConfigManager, Severity

# Start monitoring
system = MonitoringSystem()
system.start()

# Stop monitoring
system.stop()
```

### Custom Alert Handling

```python
from simple_monitor import Observer, Alert

class CustomObserver(Observer):
    def update(self, alert: Alert):
        # Your custom logic
        if alert.severity == Severity.CRITICAL:
            send_email(alert)
            
# Attach to system
system = MonitoringSystem()
system._subject.attach(CustomObserver())
```

### Access Alert Data

```python
import pandas as pd

# Read alerts from CSV
df = pd.read_csv('alerts.csv')

# Filter high severity alerts
high_alerts = df[df['severity'] == 'HIGH']

# Get alerts for specific process
process_alerts = df[df['process_name'].str.contains('chrome')]
```

---

## 🎓 Educational Value

### OOP Principles Demonstrated

✅ **Encapsulation** - Data hiding with properties  
✅ **Abstraction** - Abstract base classes (Monitor, Observer, Repository)  
✅ **Inheritance** - Monitor hierarchy, Observer hierarchy  
✅ **Polymorphism** - Platform-specific implementations  

### SOLID Principles

✅ **Single Responsibility** - Each class has one job  
✅ **Open/Closed** - Easy to extend without modification  
✅ **Liskov Substitution** - Subclasses can replace parents  
✅ **Interface Segregation** - Focused interfaces  
✅ **Dependency Inversion** - Depend on abstractions  

### Statistics

- **42+ classes** - Comprehensive OOP structure
- **10+ design patterns** - Real-world pattern usage
- **~2,800 lines of code** - Production-quality implementation
- **5 anomaly types** - All testable with provided scripts
- **Cross-platform** - Works on Windows and Linux
- **Zero database knowledge required** - Uses simple CSV files

---

## 🧪 Testing

### Unit Tests

All 5 anomaly types have dedicated test scripts:

```bash
# Run all tests sequentially
python test_memory.py   # ~10 seconds
python test_cpu.py      # ~5 seconds (stop with Ctrl+C)
python test_burst.py    # ~10 seconds
python test_network.py  # ~30 seconds (stop with Ctrl+C)
python test_thread.py   # ~30 seconds (stop with Ctrl+C)
```

### Expected Results

Each test should trigger an alert within 5-15 seconds:

| Test | Triggers | Severity | Time |
|------|----------|----------|------|
| test_memory.py | Memory alert | HIGH | ~10s |
| test_cpu.py | CPU alert | CRITICAL | ~5s |
| test_burst.py | Burst alert | CRITICAL | immediate |
| test_network.py | Network alert | HIGH | ~10s |
| test_thread.py | Thread alert | HIGH | ~15s |

---

## 🛠️ System Requirements

### Minimum Requirements

- **OS:** Windows 10/11, Linux (Ubuntu 20.04+)
- **Python:** 3.8 or higher
- **RAM:** 2 GB
- **Disk:** 100 MB

### Recommended Requirements

- **OS:** Windows 11, Ubuntu 22.04+
- **Python:** 3.10+
- **RAM:** 4 GB
- **Disk:** 500 MB

### Dependencies

```
psutil>=5.9.0      # System monitoring
streamlit>=1.20.0  # Dashboard framework
plotly>=5.13.0     # Interactive charts
pandas>=1.5.0      # Data manipulation
```

---

## 📊 Performance

### System Overhead

| Metric | Value |
|--------|-------|
| CPU Usage | ~1% |
| Memory Usage | ~50 MB |
| Disk I/O | Minimal (CSV writes) |
| Network | None (local only) |

### Response Times

| Operation | Time |
|-----------|------|
| Alert Detection | <100ms |
| Alert Storage | <50ms |
| Dashboard Load | <2s |
| Dashboard Refresh | <500ms |

---

## 🔒 Security Features

### Built-in Security Monitoring

- **Process Burst Detection** - Catches ransomware and malware spreading
- **Network Monitoring** - Detects data exfiltration attempts
- **Parent Process Tracking** - Identifies which process spawned malicious children

### Privacy

- **No data collection** - All data stays local
- **No network communication** - Except monitored processes
- **CSV storage** - Human-readable, auditable

---

## 🚧 Limitations

- **Historical Data** - Limited by CSV file size (recommend periodic rotation)
- **Real-time Dashboard** - Requires manual refresh (configurable 10-60s)
- **No Email Alerts** - Console, CSV, and log file only (easily extensible)
- **Single Machine** - Not designed for distributed monitoring

---

## 🔮 Future Enhancements

- [ ] Email/SMS alert notifications
- [ ] Machine learning-based anomaly detection
- [ ] Database support (PostgreSQL, MongoDB)
- [ ] Multi-machine monitoring
- [ ] REST API for integrations

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Your Name

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 👥 Authors

**Your Name**
- Email: chitvijoshi2646@gmail.com
- GitHub: [@ChitviJoshi](https://github.com/ChitviJoshi)
- LinkedIn: [Chitvi Joshi](https://linkedin.com/in/chitvi-joshi-2985ab324)

---

## 💬 Support

- **Documentation:** See `docs/` folder
- **Issues:** GitHub Issues
- **Discussions:** GitHub Discussions
- **Email:** your.email@example.com

---

<div align="center">

**[⬆ Back to Top](#-netsnoop-enhanced-system-monitor)**

Made with ❤️ using Python

**NetSnoop** - Comprehensive System Monitoring Made Simple

</div>
