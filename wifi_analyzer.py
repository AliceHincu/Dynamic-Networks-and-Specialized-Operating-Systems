from tkinter import ttk

from tabs.channel_graph_tab.channel_graph import ChannelGraph
from tabs.wifi_list_tab.wifi_list import WiFiList


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

        # Bind tab switching to adjust window size
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

    def on_tab_change(self, event):
        """
        Dynamically adjust window size based on the selected tab.
        """
        selected_tab = self.notebook.index(self.notebook.select())
        if selected_tab == 0:  # WiFi List Tab
            self.master.geometry("370x700")  # Set size for WiFi list
        elif selected_tab == 1:  # Channel Graph Tab
            self.master.geometry("500x400")  # Set size for graph tab