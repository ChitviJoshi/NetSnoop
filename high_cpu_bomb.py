import time

def aggressive_high_cpu_test():
    """More aggressive CPU load to ensure HIGH CPU detection"""
    print("🔺 AGGRESSIVE HIGH CPU Test - Targeting 88-92% CPU for 6 seconds")
    print("Should trigger: 🔺 HIGH CPU ALERT")
    
    start_time = time.time()
    end_time = start_time + 6.0  # Longer duration
    
    iteration_count = 0
    while time.time() < end_time:
        # More intensive work but with tiny breaks
        for i in range(25000):  # Increased work
            result = i * i * i + i * i
        
        # Minimal break to stay around 88-92%
        time.sleep(0.0003)  # Even smaller break
        
        iteration_count += 1
        if iteration_count % 300 == 0:
            elapsed = time.time() - start_time
            print(f"  High load... {elapsed:.1f}s elapsed")
    
    print("✅ AGGRESSIVE HIGH CPU test complete")

if __name__ == "__main__":
    aggressive_high_cpu_test()