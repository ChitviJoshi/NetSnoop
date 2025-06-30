# 🚀 NetSnoop - Real-Time System Monitor

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
| **🔍 Real-time Monitoring** | CPU, Memory, Process Bursts|
| **🚨 Smart Alerts** | Threshold-based anomaly detection |
| **📊 Web Dashboard** | Interactive Streamlit interface |
| **📝 Persistent Logging** | CSV logs with timestamps |


---

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Terminal 1    │    │   Data Storage   │    │    Browser      │
│                 │    │                  │    │                 │
│ acm_monitor.py  │───▶│ anomalies.csv    │───▶│ Streamlit       │
│ • CPU Monitor   │    │ • Event Logs     │    │ Dashboard       │
│ • Memory Track  │    │ • Timestamps     │    │ • Live Charts   │
│ • Process Watch │    │ • Severity Data  │    │ • Alert System  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

**Data Flow:** Monitor detects → Logs to CSV → Dashboard visualizes

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

## ⚙️ Configuration

Create `netsnoop_config.json` for custom settings:

```json
{
  "monitoring": {
    "cpu_threshold": 75,
    "memory_threshold": 80,
    "monitoring_interval": 3
  },
  "dashboard": {
    "auto_refresh_interval": 2,
    "theme": "dark"
  }
}
```

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| `netsnoop-init` not found | `pip install --upgrade netsnoop` |
| Dashboard shows no data | Check if monitor is running: `ps aux \| grep netsnoop` |
| Permission errors | `chmod +x ~/.local/bin/netsnoop-init` |
| WSL2 issues | `wsl --update` then restart |

**Debug Mode:**
```bash
export NETSNOOP_DEBUG=1
python3 -m netsnoop.acm_monitor
```

---

## 🛣️ Roadmap

- **v1.1** - Mobile dashboard, email alerts, configuration GUI
- **v1.2** - ML anomaly detection, Docker support, cloud integration  
- **v2.0** - Multi-system monitoring, plugin system, mobile app

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/name`
3. Install dev dependencies: `pip install -r requirements-dev.txt`
4. Run tests: `pytest tests/`
5. Submit pull request

**Areas for contribution:** Bug fixes, dashboard features, documentation, testing

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

**⭐ Star this repo if NetSnoop helps you monitor your systems!**

**Built with ❤️ for developers and system administrators**

</div>
