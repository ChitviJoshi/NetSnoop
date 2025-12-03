"""
NetSnoop Enhanced System Monitor

A comprehensive system monitoring application with 5 anomaly detectors:
- Memory monitoring
- CPU monitoring
- Process burst detection (security)
- Network connection monitoring (security)
- Thread monitoring

Features:
- 42+ classes demonstrating OOP principles
- 10+ design patterns
- Cross-platform (Windows & Linux)
- Real-time dashboard
- CSV-based storage
"""

__version__ = "0.2.0"
__author__ = "Chitvi Joshi"
__email__ = "cjoshi_be24@thapar.edu"

from .monitor import (
    MonitoringSystem,
    ConfigManager,
    MonitorType,
    Severity,
)

from .dashboard import DashboardApplication

__all__ = [
    "MonitoringSystem",
    "ConfigManager",
    "DashboardApplication",
    "MonitorType",
    "Severity",
]