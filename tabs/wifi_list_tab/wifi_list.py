import tkinter as tk
from tkinter import ttk

from tabs.wifi_list_tab.wifi_item_display import WiFiItemDisplay

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

    def on_frame_configure(self, event):
        """
        Adjust the scroll region to fit the content of the frame.
        """
        self.scroll_canvas.configure(scrollregion=self.scroll_canvas.bbox("all"))

    def update(self, networks):
        """
        Update the displayed Wi-Fi networks.
        """
        # Clear existing WiFi items
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()

        # Add each network to the list
        for network in networks:
            WiFiItemDisplay(self.scroll_frame, network)