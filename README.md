# 🚀 NetSnoop - Real-Time System Monitor
#      'Born to Track'

<div align="center">

[![PyPI version](https://img.shields.io/pypi/v/netsnoop?style=for-the-badge&logo=pypi)](https://pypi.org/project/netsnoop/)
[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Linux](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)](https://linux.org)

**Lightweight Linux system monitoring with real-time anomaly detection and web dashboard**

[🚀 Quick Start](#-quick-start) • [📊 Features](#-features) • [🏗️ Architecture](#️-architecture) • [📁 Project Structure](#-project-structure)

</div>

---

## 🎯 Overview

NetSnoop combines CLI monitoring with a modern web dashboard for real-time Linux system analysis. Perfect for developers, students, and sysadmins who need quick visual insights into system behavior.

**Why NetSnoop?**
- ✅ **2-minute setup** - Single pip install
- ✅ **Dual interface** - CLI + Web dashboard  
- ✅ **Smart alerts** - Automated anomaly detection
- ✅ **Beginner friendly** - No complex configuration

---

## 🚀 Quick Start

```bash
# 1. Install from PyPI
pip install netsnoop

# 2. Initialize
netsnoop-init

# 3. Start monitoring (Terminal 1)
python3 -m netsnoop.acm_monitor

# 4. Launch dashboard (Terminal 2)
streamlit run $(python3 -c "import netsnoop; print(netsnoop.__path__[0] + '/dashboard.py')")

# 5. Open browser: http://localhost:8501
```

### 🪟 Windows Users (WSL2 Required)
```bash
# Enable WSL2, install Ubuntu, then run NetSnoop inside WSL
```

---

## 📊 Features

| Feature | Description |
|---------|-------------|
| **🔍 Real-time Monitoring** | CPU, Memory, Process bursts |
| **🚨 Smart Alerts** | Threshold-based anomaly detection |
| **📊 Web Dashboard** | Interactive Streamlit interface |
| **📝 Persistent Logging** | CSV logs with timestamps |

---

## 🏗️ Architecture

### 📊 **System Data Flow**

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   /proc Files   │    │  acm_monitor.py  │    │   Dashboard     │
│                 │    │                  │    │                 │
│ /proc/stat      │───▶│ Direct File Read │───▶│ anomalies.csv   │
│ /proc/meminfo   │───▶│ Parse CPU/Memory │───▶│ Real-time UI    │
│ /proc/[pid]/    │───▶│ Process Tracking │───▶│ Alert System    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                       │                       │
        │              ┌────────▼────────┐              │
        │              │ Threshold Check │              │
        │              │ CPU > 80%? ✓    │              │
        │              │ Memory > 85%? ✓ │              │
        │              │ Process Δ > 10? │              │
        │              └─────────────────┘              │
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                               ▼
                    ┌─────────────────┐
                    │   CSV Logger    │
                    │ timestamp,type, │
                    │ severity,value  │
                    └─────────────────┘
```

### 🔄 **Monitoring Process**

| Step | Source | Process | Output |
|------|--------|---------|--------|
| **1. Data Collection** | `/proc/stat`, `/proc/meminfo` | Direct filesystem parsing | Raw metrics |
| **2. Threshold Analysis** | Raw metrics | Compare vs limits (CPU>80%, RAM>85%) | Boolean flags |
| **3. Severity Classification** | Threshold results | Critical/Warning/Info logic | Severity level |
| **4. Event Logging** | Classified events | Write to CSV with timestamp | Persistent storage |
| **5. Dashboard Update** | CSV file | Streamlit reads & visualizes | Real-time charts |

---

## 🔄 Workflow

1. **Detection** - `acm_monitor.py` scans system every 5 seconds
2. **Analysis** - Applies thresholds (CPU >80%, Memory >85%)
3. **Logging** - Saves events to `anomalies.csv` with severity levels
4. **Visualization** - Dashboard reads CSV and displays real-time charts
5. **Alerts** - Color-coded notifications (🔴 Critical, 🟡 Warning, 🟢 Info)

---

## 📁 Project Structure

```
NetSnoop/
├── netsnoop/                    # Main package
│   ├── acm_monitor.py          # Core monitoring engine
│   ├── dashboard.py            # Streamlit web dashboard  
│   ├── enhanced_anomaly_logger.py # Logging system
│   └── config.py               # Configuration
├── data/                       # Generated after init
│   ├── anomalies.csv          # Event logs
│   └── netsnoop_persistent.txt # System state
├── scripts/
│   └── netsnoop-init          # Setup script
├── docs/                      # Documentation
├── tests/                     # Test suite
├── setup.py                   # PyPI configuration
└── requirements.txt           # Dependencies
```

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| `netsnoop-init` not found | `pip install --upgrade netsnoop` |
| Dashboard shows no data | Check if monitor is running: `ps aux \| grep netsnoop` |
| Permission errors | `chmod +x ~/.local/bin/netsnoop-init` |
| WSL2 issues | `wsl --update` then restart |

---

## 🛣️ Roadmap

- **v1.1** - Desktop App, email alerts, configuration GUI
- **v1.2** - ML anomaly detection, Docker support, cloud integration  
- **v2.0** - Multi-system monitoring, plugin system, mobile app

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

---

## 📞 Support

- **📧 Email:** [chitvijoshi2646@gmail.com](mailto:chitvijoshi2646@gmail.com)
- **🐛 Issues:** [GitHub Issues](https://github.com/ChitviJoshi/NetSnoop/issues)
- **📦 PyPI:** [netsnoop package](https://pypi.org/project/netsnoop/)

---

<div align="center">


## **Built with ❤️ **

</div>
