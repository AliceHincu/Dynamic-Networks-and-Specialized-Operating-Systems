from tkinter import ttk

from tabs.channel_graph_tab.channel_graph import ChannelGraph
from tabs.packet_sniffer.packet_sniffer import PacketSniffer
from tabs.wifi_list_tab.wifi_list import WiFiList
from wifi_logic import scan_wifi, get_manufacturer, parse_security, calculate_channel


class WiFiAnalyzerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("WiFi Analyzer")
        self.master.geometry("370x700")

        # Create a notebook for tabs
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill="both", expand=True)

        # Add WiFi List Tab
        self.wifi_tab = WiFiList(self.notebook)
        self.notebook.add(self.wifi_tab.frame, text="WiFi List")

        # Add Channel Graph Tab
        self.graph_tab = ChannelGraph(self.notebook)
        self.notebook.add(self.graph_tab.frame, text="Channel Graph")

        # Add Packet Sniffer Tab
        self.sniffer_tab = PacketSniffer(self.notebook)
        self.notebook.add(self.sniffer_tab.frame, text="Packet Sniffer")

        # Bind tab switching to adjust window size
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

        # Initial Refresh
        self.refresh()

    def refresh(self):
        """
        Refresh the displayed Wi-Fi networks.
        """
        print("Refreshing Wi-Fi networks...")

        # Fetch WiFi networks
        networks = scan_wifi()
        network_details_list = []

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
            network_details_list.append(network_details)

        # Update each tab with the collected data
        self.wifi_tab.update(network_details_list)
        self.graph_tab.update(network_details_list)

        # Schedule the next refresh in 5 seconds
        self.master.after(5000, self.refresh)

    def on_tab_change(self, event):
        """
        Dynamically adjust window size based on the selected tab.
        """
        selected_tab = self.notebook.index(self.notebook.select())
        if selected_tab == 0:  # WiFi List Tab
            self.master.geometry("370x700")
        elif selected_tab == 1:  # Channel Graph Tab
            self.master.geometry("1000x800")
        elif selected_tab == 2:  # Packet Sniffer Tab
            self.master.geometry("800x600")