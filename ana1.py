import subprocess, time
for _ in range(20):
    subprocess.Popen(["sleep", "1"])
    time.sleep(0.05)
