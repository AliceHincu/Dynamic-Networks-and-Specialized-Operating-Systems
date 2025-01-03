import tkinter as tk
from PIL import ImageTk, Image
from numpy.ma.extras import column_stack

from wifi_logic import classify_signal, calculate_channel


class WiFiItemDisplay:
    def __init__(self, master, network):
        """
        Create a display for a single Wi-Fi network.
        SSID - Service Set Identifier - wi-fi name
        MAC - Media Access Control - unique address of access point
        Signal - The power of the wi-fi's signal expressed in decibels
        Frequency - The frequency of wi-fi's signal expressed in MHz - it determines the speed and range of signal
        Channel - Wi-Fi's channel computed based on frequency - it represent a subdivision of the frequency band
        Vendor - Name of manufacturer of the router, associated with the mac address
        Security - Type of wi-fi security - it analyzes the authentication key management values to determine it
        :param master: Parent widget.
        :param network: Dictionary with network details.
        """
        # Define color scheme
        bg_color = "#2C2C2C"
        text_color = "white"

        # item
        frame = tk.Frame(master, bg=bg_color, highlightthickness=1)
        frame.pack(fill='x')

        # Configure grid layout
        frame.columnconfigure(0, weight=0, minsize=40)
        frame.columnconfigure(1, weight=1)

        # Set color based on signal strength
        icon, signal_color = classify_signal(network["Signal"])

        # Load icon
        icon_image = Image.open(icon)
        icon_image = icon_image.resize((20, 20))
        wifi_icon = ImageTk.PhotoImage(icon_image)
        icon_label = tk.Label(frame, image=wifi_icon, bg=bg_color)
        icon_label.image = wifi_icon  # tkinter does not keep an internal reference, the gc deletes the object image, you need to reference it again

        # SSID and MAC
        ssid_mac_text = f"{network['SSID']} ({network['MAC']})"
        ssid_label = tk.Label(frame, text=ssid_mac_text, font=("Arial", 12, "bold"), bg=bg_color, fg=text_color)
        ssid_label.grid(row=0, column=0, columnspan=2, sticky="w", padx=10, pady=5)

        # Signal and Channel
        signal_text = f"{network['Signal']} dBm"
        signal_label = tk.Label(frame, text=signal_text, font=("Arial", 10), bg=bg_color, fg=signal_color)
        signal_label.grid(row=1, column=0, sticky="w", padx=10)

        channel_frequency_text = f"CH {network['Channel']} {network['Frequency']} MHz"
        channel_label = tk.Label(frame, text=channel_frequency_text, font=("Arial", 10), bg=bg_color, fg=text_color)
        channel_label.grid(row=1, column=1, sticky="w", padx=5)

        # Icon
        icon_label.grid(row=2, column=0, rowspan=2, sticky="nsew", padx=10, pady=5)

        # Vendor
        freq_range_text = f"Vendor: {network['Vendor']}"
        freq_label = tk.Label(frame, text=freq_range_text, font=("Arial", 10), bg=bg_color, fg=text_color)
        freq_label.grid(row=2, column=1, sticky="w", padx=5)

        # Security
        security_label = tk.Label(frame, text=network['Security'], font=("Arial", 10, "italic"), bg=bg_color,
                                  fg="#13a5b5")
        security_label.grid(row=3, column=1, sticky="w", padx=5, pady=(0, 5))
