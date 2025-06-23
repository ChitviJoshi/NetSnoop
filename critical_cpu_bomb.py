# Save as: critical_cpu_bomb.py

import time

def critical_cpu_test():
    """Maximum CPU load to trigger CRITICAL CPU (95%+)"""
    print("🧨 CRITICAL CPU Test - Targeting 95%+ CPU for 8 seconds")
    print("Should trigger: 🧨 CRITICAL CPU")
    
    start_time = time.time()
    end_time = start_time + 8.0  # Run for 8 seconds
    
    # Maximum CPU work - designed to hit 95%+ consistently
    iteration_count = 0
    while time.time() < end_time:
        # Maximum CPU work with no breaks
        for i in range(50000):  # Large work units
            result = i * i * i * i + i * i * i + i * i
        
        iteration_count += 1
        if iteration_count % 200 == 0:
            elapsed = time.time() - start_time
            print(f"  Critical load... {elapsed:.1f}s elapsed")
    
    print("✅ CRITICAL CPU test complete")

if __name__ == "__main__":
    critical_cpu_test()