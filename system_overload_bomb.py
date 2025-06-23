# Save as: system_overload_bomb.py

import time
import threading
import multiprocessing

def cpu_worker(worker_id, duration):
    """Worker function for system overload"""
    print(f"🔥 Worker {worker_id} starting CPU load for {duration}s")
    end_time = time.time() + duration
    
    while time.time() < end_time:
        # Heavy CPU work
        for i in range(20000):
            result = i * i * i * i
    
    print(f"✅ Worker {worker_id} completed")

def system_overload_test():
    """System-wide CPU overload to trigger SYSTEM OVERLOAD alerts"""
    print("🚨 SYSTEM OVERLOAD Test - Loading all CPU cores")
    print("Should trigger: 🔺 SYSTEM CPU ALERT or 🚨 CRITICAL SYSTEM OVERLOAD")
    
    # Get number of CPU cores
    cpu_count = multiprocessing.cpu_count()
    print(f"Detected {cpu_count} CPU cores - creating {cpu_count} worker threads")
    
    threads = []
    duration = 8  # Run for 8 seconds
    
    # Create one thread per CPU core
    for i in range(cpu_count):
        thread = threading.Thread(target=cpu_worker, args=(i+1, duration))
        threads.append(thread)
        thread.start()
        time.sleep(0.2)  # Stagger starts slightly
    
    print(f"🔥 All {cpu_count} workers started - system should be under heavy load")
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    print("✅ SYSTEM OVERLOAD test complete")

if __name__ == "__main__":
    system_overload_test()
