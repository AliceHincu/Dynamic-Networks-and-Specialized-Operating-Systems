import tkinter as tk
from tkinter import ttk

from tabs.wifi_list_tab.wifi_item_display import WiFiItemDisplay
from wifi_logic import scan_wifi, get_manufacturer, parse_security, calculate_channel

class WiFiList:
    def __init__(self, master):
        self.bg_color = "#2C2C2C"
        self.frame = tk.Frame(master, bg=self.bg_color)

        # Scrollable frame for WiFi items
        self.scroll_canvas = tk.Canvas(self.frame, bg=self.bg_color, highlightthickness=0)
        self.scroll_frame = tk.Frame(self.scroll_canvas, bg=self.bg_color)
        self.scrollbar = ttk.Scrollbar(self.frame, orient="vertical", command=self.scroll_canvas.yview)
        self.scroll_canvas.configure(yscrollcommand=self.scrollbar.set)

        # Configure scrollbar style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Vertical.TScrollbar",
            background=self.bg_color,
            troughcolor=self.bg_color,
            bordercolor=self.bg_color,
            arrowcolor="white"
        )

        # Configure layout
        self.scrollbar.pack(side="right", fill="y")
        self.scroll_canvas.pack(side="left", fill="both", expand=True)
        self.canvas_frame = self.scroll_canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")
        self.scroll_frame.bind("<Configure>", self.on_frame_configure)

        # Initial Refresh
        self.refresh()

    def refresh(self):
        """
        Refresh the displayed Wi-Fi networks.
        """
        print("Refreshing Wi-Fi networks...")
        # Clear existing WiFi items
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()

        # Fetch WiFi networks
        networks = scan_wifi()
        for network in networks:
            # Extract network details
            network_details = {
                "SSID": network.ssid,
                "MAC": network.bssid,
                "Signal": network.signal,
                "Frequency": network.freq // 1000,
                "Channel": calculate_channel(network.freq // 1000),
                "Vendor": get_manufacturer(network.bssid),
                "Security": parse_security(network.akm)
            }

            # Create a WiFi item display
            WiFiItemDisplay(self.scroll_frame, network_details)

        self.frame.after(5000, self.refresh)

    def on_frame_configure(self, event):
        """
        Adjust the scroll region to fit the content of the frame.
        """
        self.scroll_canvas.configure(scrollregion=self.scroll_canvas.bbox("all"))

