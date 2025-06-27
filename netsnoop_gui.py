import tkinter as tk
from tkinter import scrolledtext
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import psutil
import datetime
import threading
import time

class NetSnoopGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetSnoop - Real-Time System Monitor")

        # Create Matplotlib Figure for 9 subplots
        self.fig, self.axs = plt.subplots(3, 3, figsize=(10, 7))
        plt.tight_layout()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Anomaly Log Text Box
        self.log_text = scrolledtext.ScrolledText(root, height=10, font=("Courier", 10))
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Buffers
        self.time_points = []
        self.cpu_usage = []
        self.per_core_usage = []
        self.cpu_freq = []
        self.memory_usage = []
        self.swap_usage = []
        self.disk_usage = []
        self.disk_read_speed = []
        self.disk_write_speed = []
        self.net_upload_speed = []
        self.net_download_speed = []
        self.process_count = []
        self.anomaly_log = []

        self.prev_disk = psutil.disk_io_counters()
        self.prev_net = psutil.net_io_counters()
        self.time_counter = 0

        # Start update loop
        self.running = True
        threading.Thread(target=self.update_loop, daemon=True).start()

    def log_anomaly(self, message):
        timestamp = datetime.datetime.now().strftime("[%H:%M:%S]")
        log_entry = f"{timestamp} {message}\n"
        self.anomaly_log.append(log_entry)
        if len(self.anomaly_log) > 50:
            self.anomaly_log.pop(0)
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, "".join(self.anomaly_log))
        self.log_text.see(tk.END)

    def update_loop(self):
        while self.running:
            self.update_metrics()
            time.sleep(1)

    def update_metrics(self):
        self.time_points.append(self.time_counter)

        cpu = psutil.cpu_percent()
        cores = psutil.cpu_percent(percpu=True)
        freq = psutil.cpu_freq().current
        mem = psutil.virtual_memory().percent
        swap = psutil.swap_memory().percent
        disk = psutil.disk_usage('/').percent
        proc = len(psutil.pids())

        current_disk = psutil.disk_io_counters()
        read_speed = (current_disk.read_bytes - self.prev_disk.read_bytes) / (1024 * 1024)
        write_speed = (current_disk.write_bytes - self.prev_disk.write_bytes) / (1024 * 1024)
        self.prev_disk = current_disk

        current_net = psutil.net_io_counters()
        upload_speed = (current_net.bytes_sent - self.prev_net.bytes_sent) / (1024 * 1024)
        download_speed = (current_net.bytes_recv - self.prev_net.bytes_recv) / (1024 * 1024)
        self.prev_net = current_net

        # Append data
        self.cpu_usage.append(cpu)
        self.per_core_usage.append(cores)
        self.cpu_freq.append(freq)
        self.memory_usage.append(mem)
        self.swap_usage.append(swap)
        self.disk_usage.append(disk)
        self.disk_read_speed.append(read_speed)
        self.disk_write_speed.append(write_speed)
        self.net_upload_speed.append(upload_speed)
        self.net_download_speed.append(download_speed)
        self.process_count.append(proc)

        max_points = 60
        for lst in [self.time_points, self.cpu_usage, self.cpu_freq, self.memory_usage,
                    self.swap_usage, self.disk_usage, self.disk_read_speed, self.disk_write_speed,
                    self.net_upload_speed, self.net_download_speed, self.process_count]:
            if len(lst) > max_points:
                lst.pop(0)
        while len(self.per_core_usage) > max_points:
            self.per_core_usage.pop(0)

        # Clear previous plots
        for ax in self.axs.flat:
            ax.cla()

        # Plot CPU Usage
        self.axs[0, 0].plot(self.time_points, self.cpu_usage, color='red')
        self.axs[0, 0].set_title('CPU Usage (%)')
        self.axs[0, 0].set_ylim(0, 100)
        if len(self.cpu_usage) >= 3 and all(u > 90 for u in self.cpu_usage[-3:]):
            self.axs[0, 0].text(0.5, 0.5, 'High CPU Spike!', color='red', fontsize=10, ha='center', transform=self.axs[0, 0].transAxes)
            self.log_anomaly('High CPU Spike!')

        # Per-Core CPU
        for i in range(len(cores)):
            core_vals = [x[i] for x in self.per_core_usage]
            self.axs[0, 1].plot(self.time_points, core_vals, label=f'Core {i}')
        self.axs[0, 1].set_title('Per-Core CPU Usage (%)')
        self.axs[0, 1].set_ylim(0, 100)
        self.axs[0, 1].legend(fontsize=6)

        # CPU Frequency
        self.axs[0, 2].plot(self.time_points, self.cpu_freq, color='orange')
        self.axs[0, 2].set_title('CPU Frequency (MHz)')
        if len(self.cpu_freq) >= 5 and self.cpu_usage[-1] > 80:
            avg_freq = sum(self.cpu_freq[-5:]) / 5
            if avg_freq < 0.7 * max(self.cpu_freq):
                self.axs[0, 2].text(0.5, 0.5, 'Thermal Throttling!', color='purple', fontsize=8, ha='center', transform=self.axs[0, 2].transAxes)
                self.log_anomaly('Thermal Throttling Detected!')

        # Memory Usage
        self.axs[1, 0].plot(self.time_points, self.memory_usage, color='green')
        self.axs[1, 0].set_title('Memory Usage (%)')
        self.axs[1, 0].set_ylim(0, 100)
        if len(self.memory_usage) >= 6 and (self.memory_usage[-1] - self.memory_usage[-6]) > 20:
            self.axs[1, 0].text(0.5, 0.5, 'Memory Surge!', color='yellow', fontsize=10, ha='center', transform=self.axs[1, 0].transAxes)
            self.log_anomaly('Memory Surge Detected!')

        # Swap Usage
        self.axs[1, 1].plot(self.time_points, self.swap_usage, color='purple')
        self.axs[1, 1].set_title('Swap Usage (%)')
        self.axs[1, 1].set_ylim(0, 100)

        # Disk Usage
        self.axs[1, 2].plot(self.time_points, self.disk_usage, color='blue')
        self.axs[1, 2].set_title('Disk Usage (%)')
        self.axs[1, 2].set_ylim(0, 100)
        if self.disk_usage[-1] > 95:
            self.axs[1, 2].text(0.5, 0.5, 'Disk Almost Full!', color='red', fontsize=10, ha='center', transform=self.axs[1, 2].transAxes)
            self.log_anomaly('Disk Almost Full!')

        # Disk I/O
        self.axs[2, 0].plot(self.time_points, self.disk_read_speed, label='Read MBps', color='cyan')
        self.axs[2, 0].plot(self.time_points, self.disk_write_speed, label='Write MBps', color='magenta')
        self.axs[2, 0].set_title('Disk I/O Speed')
        self.axs[2, 0].legend(fontsize=6)

        # Network Speed
        self.axs[2, 1].plot(self.time_points, self.net_download_speed, label='Download MBps', color='navy')
        self.axs[2, 1].plot(self.time_points, self.net_upload_speed, label='Upload MBps', color='brown')
        self.axs[2, 1].set_title('Network Speed')
        self.axs[2, 1].legend(fontsize=6)

        # Process Count
        self.axs[2, 2].plot(self.time_points, self.process_count, color='black')
        self.axs[2, 2].set_title('Running Processes')
        if len(self.process_count) >= 11:
            old = self.process_count[-11]
            new = self.process_count[-1]
            if abs(new - old) > 0.3 * old:
                self.axs[2, 2].text(0.5, 0.5, 'Abnormal Process Count!', color='orange', fontsize=8, ha='center', transform=self.axs[2, 2].transAxes)
                self.log_anomaly('Abnormal Process Count Detected!')

        self.canvas.draw()
        self.time_counter += 1

if __name__ == "__main__":
    root = tk.Tk()
    app = NetSnoopGUI(root)
    root.mainloop()
