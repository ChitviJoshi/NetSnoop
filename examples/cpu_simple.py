#!/usr/bin/env python3
"""
Test CPU Anomaly
This script will trigger a HIGH CPU alert (>90%)
"""

import time

print("🔺 CPU Test - Starting infinite loop...")
print("   This will use ~100% of one CPU core")
print("   Your monitor should show a HIGH CPU alert within 5 seconds")
print("\n📊 Press Ctrl+C to stop\n")

start_time = time.time()

try:
    while True:
        # Infinite loop to max out CPU
        x = 1 + 1
        
        # Show status every 5 seconds
        if time.time() - start_time > 5:
            print("⏱️  Still running... (Press Ctrl+C to stop)")
            start_time = time.time()

except KeyboardInterrupt:
    print("\n👋 Test complete!")