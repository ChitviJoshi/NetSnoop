#!/usr/bin/env python3
"""
Test Thread Anomaly
This script will trigger a HIGH thread alert (>50 threads)
"""

import threading
import time

print("🧵 Thread Test - Creating multiple threads...")
print("   This will create 60 threads")
print("   Your monitor should show a HIGH THREAD alert within 15 seconds")

threads = []
stop_flag = threading.Event()

def worker_thread(thread_id):
    """Simple worker thread that just sleeps"""
    while not stop_flag.is_set():
        time.sleep(0.1)

try:
    # Create 60 threads
    for i in range(60):
        thread = threading.Thread(target=worker_thread, args=(i,), daemon=True)
        thread.start()
        threads.append(thread)
        print(f"   Created thread {i+1}/60")
    
    print(f"\n✅ All {len(threads)} threads created!")
    print("   Your monitor should show a THREAD alert now")
    print("\n⏳ Threads are running... Press Ctrl+C to stop")
    
    # Keep main thread alive
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print("\n🛑 Stopping threads...")
    stop_flag.set()
    
    # Wait a bit for threads to finish
    time.sleep(1)
    
    print("👋 Test complete!")