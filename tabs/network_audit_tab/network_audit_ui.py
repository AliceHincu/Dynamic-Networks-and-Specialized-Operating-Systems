import socket
import threading
import time
import tkinter as tk
from tkinter import ttk

import psutil
from matplotlib import pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from tabs.network_audit_tab.network_audit_logic import NetworkAuditLogic

class NetworkAuditUI:
    def __init__(self):
        # Create a new Tkinter window
        self.master = tk.Tk()
        self.master.title("Network Audit")
        self.master.geometry("1500x1000")
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

        # Init UI
        self.frame = tk.Frame(self.master, bg="#2C2C2C")
        self.frame.pack(fill="both", expand=True)
        self.table_frame = None
        self.graph_frame = None
        self.control_frame = None
        self.canvas = None
        self.ax = None
        self.figure = None
        self.scrollbar = None
        self.tree = None
        self.stop_button = None
        self.start_button = None
        self.setup_ui()

        self.logic = NetworkAuditLogic()

        self.sniffing_active = False
        self.selected_connection = None  # Currently selected connection to show bps graph
        self.stop_event = threading.Event()
        self.graph_stop_event = threading.Event()
        self.graph_thread = None

        # Start monitoring in a separate thread
        self.monitor_thread = threading.Thread(target=self.monitor_connections)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def setup_ui(self):
        """Setup UI components"""
        self.setup_ui_bps_table()
        self.setup_ui_bps_graph()
        self.setup_ui_controls()

    def setup_ui_bps_table(self):
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

    def setup_ui_bps_graph(self):
        # Bottom Frame for Graph
        self.graph_frame = tk.Frame(self.frame, bg="#2C2C2C")
        self.graph_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Matplotlib Figure for Traffic Graph
        self.figure = plt.Figure(figsize=(5, 3), dpi=100)
        self.ax = self.figure.add_subplot(1, 1, 1)
        self.ax.set_title("Real-Time Traffic for Selected Connection")
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Traffic (bps)")

        # Embed Figure in Tkinter
        self.canvas = FigureCanvasTkAgg(self.figure, self.graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    def setup_ui_controls(self):
        """Setup the Start/Stop Sniffing Buttons."""
        self.control_frame = tk.Frame(self.frame, bg="#2C2C2C")
        self.control_frame.pack(fill="x", padx=10, pady=5)

        # Start Button
        self.start_button = tk.Button(
            self.control_frame,
            text="Start Sniffing",
            command=self.start_sniffing,
            bg="#28a745",
            fg="white",
        )
        self.start_button.pack(side="left", padx=10)

        # Stop Button
        self.stop_button = tk.Button(
            self.control_frame,
            text="Stop Sniffing",
            command=self.stop_sniffing,
            bg="#dc3545",
            fg="white",
            state="disabled",
        )
        self.stop_button.pack(side="left", padx=10)

    def on_row_select(self, event):
        """Handle row selection in the table."""
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0], "values")
            self.selected_connection = f"{values[0]} -> {values[1]}"  # Source -> Destination

            # Restart the graph thread for real-time updates
            self.start_graph_thread()

    def start_sniffing(self):
        """Start packet sniffing."""
        if not self.sniffing_active:
            self.sniffing_active = True
            self.logic.start_sniffing()
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")

    def stop_sniffing(self):
        """Stop packet sniffing."""
        if self.sniffing_active:
            self.sniffing_active = False
            self.logic.stop_sniffing()
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")

    def monitor_connections(self):
        """Monitor connections and update table."""
        while not self.stop_event.is_set():
            traffic_data = self.logic.get_traffic_data()  # Get thread-safe copy
            self.logic.add_zero_traffic()  # Ensure zero traffic is added for inactive connections
            self.update_table(traffic_data)
            time.sleep(1)  # Update every second

    def update_table(self, traffic_data):
        """Update the connection table with live data."""
        # Create a map of existing items in the table for efficient updates
        existing_items = {
            self.tree.item(child, 'values')[0] + " -> " + self.tree.item(child, 'values')[1]: child
            for child in self.tree.get_children()
        }

        # Sort traffic data by Source and Destination IP
        sorted_data = sorted(
            traffic_data.items(),
            key=lambda item: (item[0].split(" -> ")[0], item[0].split(" -> ")[1])
        )

        # Iterate over sorted traffic data to update or add rows
        for connection, data in sorted_data:
            src, dest = connection.split(" -> ")
            latest_bps = data["bps"][-1] if data["bps"] else 0  # Get the latest bps value or 0
            location = self.logic.resolve_location(dest.split(":")[0])
            protocol = data["protocol"]
            app_name = self.logic.get_application_name(src.split(":")[0], int(src.split(":")[1]),
                                                       dest.split(":")[0], int(dest.split(":")[1]))

            if connection in existing_items:
                self.tree.item(
                    existing_items[connection],
                    values=(src, dest, protocol, f"{latest_bps:.2f} bps", app_name, location),
                )
            else:
                self.tree.insert(
                    "",
                    "end",
                    iid=connection,
                    values=(src, dest, protocol, f"{latest_bps:.2f} bps", app_name, location),
                )

        # Remove rows for connections that are no longer active
        current_keys = {item[0] for item in sorted_data}
        for connection in list(existing_items.keys()):
            if connection not in current_keys:
                self.tree.delete(existing_items[connection])

    def start_graph_thread(self):
        """Start a thread for real-time graph updates."""
        if self.graph_thread and self.graph_thread.is_alive():
            self.graph_stop_event.set()
            self.graph_thread.join()

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

        if self.selected_connection and self.selected_connection in self.logic.traffic_data:
            times = self.logic.traffic_data[self.selected_connection]["time"]
            values = self.logic.traffic_data[self.selected_connection]["bps"]
            self.ax.plot(times, values, label=self.selected_connection)
            self.ax.legend()

        self.canvas.draw()

    def on_close(self):
        """Handle application close event."""
        self.stop_sniffing()
        self.stop()
        self.master.destroy()

    def stop(self):
        """Stop monitoring."""
        self.stop_event.set()
        self.graph_stop_event.set()
        self.monitor_thread.join()
        if self.graph_thread and self.graph_thread.is_alive():
            self.graph_thread.join()
