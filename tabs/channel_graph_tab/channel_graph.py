import tkinter as tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

class ChannelGraph:
    """
    todo
    """
    def __init__(self, master):
        self.frame = tk.Frame(master, bg="white")

        # Create a graph
        self.figure = plt.Figure(figsize=(5, 4), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.channel_graph = FigureCanvasTkAgg(self.figure, self.frame)
        self.channel_graph.get_tk_widget().pack(fill="both", expand=True)

    def update_graph(self, channel_counts):
        """
        Update the graph with the latest channel usage data.
        """
        self.ax.clear()
        channels = list(channel_counts.keys())
        counts = list(channel_counts.values())
        self.ax.bar(channels, counts, color="blue")
        self.ax.set_title("Channel Utilization")
        self.ax.set_xlabel("Channels")
        self.ax.set_ylabel("Number of Networks")
        self.ax.grid(True)
        self.channel_graph.draw()
