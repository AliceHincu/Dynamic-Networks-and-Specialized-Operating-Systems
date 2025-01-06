import tkinter as tk
from tkinter import ttk
import psutil
from scapy.all import *
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import requests

import time

class NetworkAudit:
    def __init__(self, master):
        self.frame = tk.Frame(master, bg="#2C2C2C")
        self.setup_ui()

        # Initialize data structures
        self.traffic_data = {}  # Store traffic data for each connection
        self.traffic_bytes = {}  # Store byte counters for each connection
        self.location_cache = {}  # Cache for storing location results
        self.selected_connection = None  # Currently selected connection
        self.stop_event = threading.Event()
        self.graph_stop_event = threading.Event()
        self.graph_thread = None

        # Start monitoring in a separate thread
        self.monitor_thread = threading.Thread(target=self.monitor_connections)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def get_traffic(self, src_ip, src_port, dest_ip, dest_port):
        """Calculate traffic in bps for a specific connection."""
        key = f"{src_ip}:{src_port} -> {dest_ip}:{dest_port}"
        if key not in self.traffic_data:
            self.traffic_data[key] = {"time": [], "bps": []}
            self.traffic_bytes[key] = {"last_bytes": 0, "last_time": time.time()}

        # Capture packet bytes using psutil counters
        current_time = time.time()
        counters = psutil.net_io_counters(pernic=False)
        total_bytes = counters.bytes_sent + counters.bytes_recv

        # Calculate bytes per second (bps)
        elapsed_time = current_time - self.traffic_bytes[key]["last_time"]
        bps = 0
        if elapsed_time > 0:
            bps = (total_bytes - self.traffic_bytes[key]["last_bytes"]) * 8 / elapsed_time

        # Update last bytes and time
        self.traffic_bytes[key]["last_bytes"] = total_bytes
        self.traffic_bytes[key]["last_time"] = current_time

        # Append data for graph
        self.traffic_data[key]["time"].append(current_time)
        self.traffic_data[key]["bps"].append(bps)

        # Keep only the last 60 seconds of data
        if len(self.traffic_data[key]["time"]) > 60:
            self.traffic_data[key]["time"].pop(0)
            self.traffic_data[key]["bps"].pop(0)

        return bps

    def setup_ui(self):
        """Setup UI components (table and graph)."""
        # Top Frame for Connection Table
        self.table_frame = tk.Frame(self.frame, bg="#2C2C2C")
        self.table_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Connection Table
        self.tree = ttk.Treeview(
            self.table_frame,
            columns=("Source", "Destination", "Protocol", "Traffic", "Application", "Location"),
            show="headings"
        )
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Traffic", text="Traffic (bps)")
        self.tree.heading("Application", text="Application")
        self.tree.heading("Location", text="Location")
        self.tree.pack(side="left", fill="both", expand=True)

        # Scrollbar for Table
        self.scrollbar = tk.Scrollbar(self.table_frame, command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.config(yscrollcommand=self.scrollbar.set)

        # Bind event for row selection
        self.tree.bind("<<TreeviewSelect>>", self.on_row_select)

        # Bottom Frame for Graph
        self.graph_frame = tk.Frame(self.frame, bg="#2C2C2C")
        self.graph_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Matplotlib Figure for Traffic Graph
        self.figure = plt.Figure(figsize=(5, 3), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.ax.set_title("Real-Time Traffic for Selected Connection")
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Traffic (bps)")

        # Embed Figure in Tkinter
        self.canvas = FigureCanvasTkAgg(self.figure, self.graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    def monitor_connections(self):
        """Monitor connections and update table."""
        while not self.stop_event.is_set():
            connections = psutil.net_connections(kind="inet")
            self.update_table(connections)
            time.sleep(1)  # Update every second

    def update_table(self, connections):
        """Update the connection table with live data."""
        existing_items = {self.tree.item(child, 'values')[0]: child for child in self.tree.get_children()}
        current_keys = set()

        for conn in connections:
            if conn.laddr and conn.raddr:
                src = f"{conn.laddr.ip}:{conn.laddr.port}"
                dest = f"{conn.raddr.ip}:{conn.raddr.port}"
                protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                traffic = self.get_traffic(conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port)
                app_name = self.get_application_name(conn.pid)

                # Initially display "Getting location..."
                if conn.raddr.ip not in self.location_cache:
                    location = "Getting location..."
                    threading.Thread(target=self.resolve_location, args=(conn.raddr.ip,)).start()
                else:
                    location = self.location_cache[conn.raddr.ip]

                current_keys.add(src)

                if src in existing_items:
                    self.tree.item(existing_items[src], values=(src, dest, protocol, traffic, app_name, location))
                else:
                    self.tree.insert("", "end", values=(src, dest, protocol, traffic, app_name, location))

        # Remove rows that are no longer present
        for key in existing_items.keys() - current_keys:
            self.tree.delete(existing_items[key])

    def on_row_select(self, event):
        """Handle row selection in the table."""
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0], "values")
            self.selected_connection = f"{values[0]} -> {values[1]}"  # Source -> Destination

            # Restart the graph thread for real-time updates
            self.start_graph_thread()

    def start_graph_thread(self):
        """Start a thread for real-time graph updates."""
        # Stop the previous graph thread if it exists
        if self.graph_thread and self.graph_thread.is_alive():
            self.graph_stop_event.set()
            self.graph_thread.join()

        # Reset the stop event and start a new thread
        self.graph_stop_event.clear()
        self.graph_thread = threading.Thread(target=self.update_graph_real_time)
        self.graph_thread.daemon = True
        self.graph_thread.start()

    def update_graph_real_time(self):
        """Update the traffic graph for the selected connection in real time."""
        while not self.graph_stop_event.is_set():
            self.update_graph()
            time.sleep(1)

    def update_graph(self):
        """Update the traffic graph for the selected connection."""
        self.ax.clear()
        self.ax.set_title("Real-Time Traffic for Selected Connection")
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Traffic (bps)")

        if self.selected_connection and self.selected_connection in self.traffic_data:
            times = self.traffic_data[self.selected_connection]["time"]
            values = self.traffic_data[self.selected_connection]["bps"]
            self.ax.plot(times, values, label=self.selected_connection)
            self.ax.legend()

        self.canvas.draw()

    def stop(self):
        """Stop monitoring."""
        self.stop_event.set()
        self.graph_stop_event.set()
        self.monitor_thread.join()
        if self.graph_thread and self.graph_thread.is_alive():
            self.graph_thread.join()

    def get_application_name(self, pid):
        """Get the application name for a given process ID."""
        try:
            proc = psutil.Process(pid)
            return proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "Unknown"

    def resolve_location(self, ip):
        """Resolve geolocation information for an IP address."""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            data = response.json()
            if data["status"] == "success":
                location = f"{data['city']}, {data['regionName']}, {data['country']}"
            else:
                location = "Unknown"
        except Exception:
            location = "Unknown"

        self.location_cache[ip] = location