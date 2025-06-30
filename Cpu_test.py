#!/usr/bin/env python3
"""
Extreme CPU Test - Guaranteed to trigger EXTREME CPU alert
This script will consume maximum CPU to test monitoring system
"""

import threading
import time
import multiprocessing
import math

def cpu_burn_worker(worker_id, duration=60):
    """Single worker that burns CPU cycles"""
    print(f"🔥 Worker {worker_id} starting CPU burn for {duration} seconds...")
    
    start_time = time.time()
    counter = 0
    
    # Infinite loop with heavy computation
    while time.time() - start_time < duration:
        # Heavy mathematical operations
        for i in range(1000):
            # Complex calculations to max out CPU
            result = math.sqrt(i) * math.sin(i) * math.cos(i)
            result = math.factorial(i % 10)  # Expensive operation
            counter += 1
        
        # Brief check every 1000 iterations
        if counter % 100000 == 0:
            elapsed = time.time() - start_time
            print(f"Worker {worker_id}: {elapsed:.1f}s elapsed, counter: {counter}")

def extreme_cpu_test():
    """Launch extreme CPU test using all available cores"""
    print("🚨 EXTREME CPU TEST STARTING 🚨")
    print("This will consume maximum CPU for 60 seconds")
    print("Monitor should detect EXTREME CPU alert!")
    print("-" * 50)
    
    # Get number of CPU cores
    num_cores = multiprocessing.cpu_count()
    print(f"🖥️  Detected {num_cores} CPU cores")
    
    # Create one thread per core for maximum CPU usage
    threads = []
    
    for i in range(num_cores):
        thread = threading.Thread(
            target=cpu_burn_worker, 
            args=(i+1, 60),  # Run for 60 seconds
            daemon=True
        )
        threads.append(thread)
        thread.start()
        print(f"🔥 Started CPU burn thread {i+1}")
    
    print(f"\n💥 ALL {num_cores} THREADS RUNNING - CPU SHOULD BE AT 100%!")
    print("⏰ Test will run for 60 seconds...")
    print("🎯 Your monitor should detect EXTREME CPU alert!")
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    print("\n✅ Extreme CPU test completed!")
    print("🎯 Check your monitor for EXTREME CPU alerts!")

if __name__ == "__main__":
    print("🔥 EXTREME CPU TEST SCRIPT 🔥")
    print("=" * 40)
    
    try:
        extreme_cpu_test()
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"❌ Error during test: {e}")