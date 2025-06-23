# Save as: burst_test.py

import subprocess
import time

def burst_spawn_test():
    """Test rapid process spawning - should trigger burst anomaly"""
    print("🧪 Starting burst spawn test - will create 15 processes rapidly")
    
    processes = []
    for i in range(15):
        # Spawn sleep processes rapidly
        proc = subprocess.Popen(['sleep', '2'])
        processes.append(proc)
        print(f"Spawned process {i+1}/15 (PID: {proc.pid})")
        time.sleep(0.1)  # Very short delay
    
    print("✅ Burst spawn complete - waiting for processes to finish")
    
    # Wait for all to complete
    for proc in processes:
        proc.wait()
    
    print("🏁 Burst test finished")

if __name__ == "__main__":
    burst_spawn_test()