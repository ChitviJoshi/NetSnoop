#!/usr/bin/env python3
"""
Test Memory Anomaly
This script will trigger a HIGH memory alert (>500 MB)
"""

print("🧠 Memory Test - Creating large data structure...")
print("   This will use ~600 MB of RAM")

# Create a large list that uses lots of memory
big_data = [0] * (150 * 1024 * 1024)  # ~600 MB

print("✅ Memory allocated!")
print("   Your monitor should show a HIGH MEMORY alert within 10 seconds")
print("\n📊 Wait for alert, then press Ctrl+C to exit")

try:
    input()
except KeyboardInterrupt:
    print("\n👋 Test complete!")