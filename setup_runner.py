#!/usr/bin/env python3
"""
Simple Setup Script for System Monitor Dashboard
Run this first to set everything up
"""

import os
import subprocess
import sys

def install_packages():
    """Install required packages"""
    packages = ["streamlit", "pandas", "plotly"]
    
    print("📦 Installing required packages...")
    for package in packages:
        try:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✅ {package} installed")
        except:
            print(f"❌ Failed to install {package}")
            print(f"Try manually: pip install {package}")
            return False
    return True

def create_csv_file():
    """Create anomalies.csv with proper headers"""
    headers = "timestamp,anomaly_type,severity,process_name,pid,user,command,description,cpu_usage,memory_usage_mb,duration,parent_pid,session_id,additional_info\n"
    
    try:
        if not os.path.exists("anomalies.csv"):
            with open("anomalies.csv", "w") as f:
                f.write(headers)
            print("✅ Created anomalies.csv")
        else:
            print("📄 anomalies.csv already exists")
        return True
    except Exception as e:
        print(f"❌ Error creating CSV: {e}")
        return False

def create_run_scripts():
    """Create convenient run scripts"""
    
    # Windows batch files
    dashboard_bat = """@echo off
echo 🚀 Starting System Monitor Dashboard...
echo 📊 Dashboard will be available at: http://localhost:8501
echo 🛑 Press Ctrl+C to stop
streamlit run dashboard.py --server.port 8501
pause
"""
    
    monitor_bat = """@echo off
echo 🔍 Starting System Monitor...
echo 📝 Logs will be saved to: netsnoop_persistent.txt
echo 📊 Anomalies will be saved to: anomalies.csv
echo 🛑 Press Ctrl+C to stop
python acm_monitor.py
pause
"""
    
    # Linux/Mac shell scripts
    dashboard_sh = """#!/bin/bash
echo "🚀 Starting System Monitor Dashboard..."
echo "📊 Dashboard will be available at: http://localhost:8501"
echo "🛑 Press Ctrl+C to stop"
streamlit run dashboard.py --server.port 8501
"""
    
    monitor_sh = """#!/bin/bash
echo "🔍 Starting System Monitor..."
echo "📝 Logs will be saved to: netsnoop_persistent.txt"
echo "📊 Anomalies will be saved to: anomalies.csv"
echo "🛑 Press Ctrl+C to stop"
python3 acm_monitor.py
"""
    
    try:
        # Create batch files for Windows
        with open("run_dashboard.bat", "w") as f:
            f.write(dashboard_bat)
        with open("run_monitor.bat", "w") as f:
            f.write(monitor_bat)
        
        # Create shell scripts for Linux/Mac
        with open("run_dashboard.sh", "w") as f:
            f.write(dashboard_sh)
        with open("run_monitor.sh", "w") as f:
            f.write(monitor_sh)
        
        # Make shell scripts executable
        try:
            os.chmod("run_dashboard.sh", 0o755)
            os.chmod("run_monitor.sh", 0o755)
        except:
            pass  # Windows doesn't need chmod
        
        print("✅ Created run scripts")
        return True
    except Exception as e:
        print(f"❌ Error creating run scripts: {e}")
        return False

def create_sample_data():
    """Add sample data for testing"""
    sample_data = [
        "2024-01-15 14:30:15,High CPU Usage,HIGH,chrome,1234,user1,/usr/bin/google-chrome,High CPU usage: 85.2%,85.2,0.0,5s,1000,20240115_14,",
        "2024-01-15 14:31:22,Process Burst,MEDIUM,bash,1235,user1,/bin/bash,Process burst: 12 processes spawned rapidly,0.0,0.0,,1001,20240115_14,burst_count:12",
        "2024-01-15 14:32:45,High Memory Usage,HIGH,firefox,1236,user1,/usr/bin/firefox,High memory usage: 512.3 MB,0.0,512.3,,1000,20240115_14,",
    ]
    
    try:
        # Check if CSV has data
        with open("anomalies.csv", "r") as f:
            lines = f.readlines()
        
        if len(lines) <= 1:  # Only header or empty
            with open("anomalies.csv", "a") as f:
                for line in sample_data:
                    f.write(line + "\n")
            print("✅ Added sample data")
        else:
            print("📊 CSV already has data")
        return True
    except Exception as e:
        print(f"❌ Error adding sample data: {e}")
        return False

def main():
    print("🖥️  System Monitor Dashboard Setup")
    print("="*50)
    
    print(f"✅ Python {sys.version.split()[0]} detected")
    
    if not install_packages():
        return False
    
    if not create_csv_file():
        return False
    
    if not create_run_scripts():
        return False
    
    if not create_sample_data():
        return False
    
    print("\n" + "="*60)
    print("🎉 SETUP COMPLETE!")
    print("="*60)
    print()
    print("📋 NEXT STEPS:")
    print()
    print("1️⃣  Start the System Monitor:")
    print("   python acm_monitor.py")
    print("   OR double-click: run_monitor.bat/.sh")
    print()
    print("2️⃣  In another terminal, start the Dashboard:")
    print("   streamlit run dashboard.py")
    print("   OR double-click: run_dashboard.bat/.sh")
    print()
    print("3️⃣  Open browser to: http://localhost:8501")
    print()
    print("📁 FILES READY:")
    print("   ✅ enhanced_anomaly_logger.py")
    print("   ✅ dashboard.py")
    print("   ✅ acm_monitor.py")
    print("   ✅ anomalies.csv")
    print("   ✅ requirements.txt")
    print("   ✅ run scripts")
    print()
    print("="*60)
    
    return True

if __name__ == "__main__":
    try:
        if main():
            print("✅ Setup completed successfully!")
        else:
            print("❌ Setup failed!")
    except KeyboardInterrupt:
        print("\n🛑 Setup interrupted")
    except Exception as e:
        print(f"❌ Setup error: {e}")