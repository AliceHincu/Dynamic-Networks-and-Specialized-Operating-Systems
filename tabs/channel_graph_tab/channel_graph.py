import tkinter as tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from matplotlib.patches import Polygon


class ChannelGraph:
    """
    Since the application is running on Windows, Monitor Mode is not supported by the integrated Intel Wi-Fi 6 AX201
    adapter. As a result, it is not possible to detect the actual channel bandwidth (20 MHz, 40 MHz, or 80 MHz) used by
    the detected networks.

    To overcome this limitation, the application assumes a default bandwidth of 20 MHz for all networks when plotting
    the channel utilization graph. This ensures basic functionality, but it may not reflect the true channel widths in
    use.
    """
    def __init__(self, master):
        self.frame = tk.Frame(master, bg="#2C2C2C")

        # Create main container for graph and legend
        self.main_container = tk.Frame(self.frame, bg="#2C2C2C")
        self.main_container.pack(fill="both", expand=True)

        # Graph Frame
        self.graph_frame = tk.Frame(self.main_container, bg="#2C2C2C")
        self.graph_frame.pack(side="left", fill="both", expand=True)

        # Create a graph
        self.figure = plt.Figure(figsize=(6, 4), dpi=100)
        self.ax = self.figure.add_subplot(111)

        # Configure the axis using the helper function
        configure_axis(self.ax)

        # Embed the figure in Tkinter
        self.channel_graph = FigureCanvasTkAgg(self.figure, self.graph_frame)
        self.channel_graph.get_tk_widget().pack(fill="both", expand=True)

        # Legend Frame
        self.legend_frame = tk.Frame(self.main_container, bg="white", width=200)
        self.legend_frame.pack(side="right", fill="y", padx=5)

        # Predefined color palette
        self.colors = plt.cm.tab10.colors
        # Persistent color mapping for networks
        self.color_mapping = {}
        # Track text annotations and trapezoids
        self.text_objects = []
        self.trapezoids = []

    def update(self, networks):
        """
        Update the graph to show channel utilization as flat bars (rectangular areas)
        and move the legend to the right of the graph.
        """
        self.clear_graph_and_legend()
        self.draw_bars_and_legend(networks)

        # Draw the updated graph
        self.ax.grid(True)
        self.channel_graph.draw()

    def draw_bars_and_legend(self, networks):
        sorted_networks = sorted(networks, key=lambda n: n["Channel"])

        # Plot each network as a bar
        for idx, network in enumerate(sorted_networks):
            ssid = network["SSID"]
            mac = network["MAC"]
            channel = network["Channel"]
            signal = network["Signal"]

            if channel > 14:
                continue

            name = ssid if ssid else mac

            # Assign a unique color to each network
            if name not in self.color_mapping:
                self.color_mapping[name] = self.colors[len(self.color_mapping) % len(self.colors)]

            color = self.color_mapping[name]

            # Define the flat bar coordinates
            x_start = max(channel - 2, 1)
            x_end = min(channel + 2, 14)
            x_mid = channel
            y_bottom = -90  # Bottom of the bar
            y_top = signal  # Top of the bar (signal strength)

            vertices = [
                (x_start, y_bottom),  # Bottom-left
                (x_end, y_bottom),  # Bottom-right
                (x_mid + 1, y_top),  # Top-right (slightly narrower)
                (x_mid - 1, y_top)  # Top-left (slightly narrower)
            ]

            # Create and add the trapezoid to the plot
            trapezoid = Polygon(
                vertices, closed=True,
                facecolor=color, alpha=0.5,  # Semi-transparent fill
                edgecolor="black", linewidth=2  # Opaque, thick border
            )
            self.ax.add_patch(trapezoid)
            self.trapezoids.append(trapezoid)

            # Add label for the SSID above the bar
            text = self.ax.text(
                channel,
                signal + 2,  # Slightly above the bar
                f"{name} (CH {channel})",
                fontsize=8,
                color=rgb_to_hex(color),
                ha="center"
            )
            self.text_objects.append(text)

            # Add to the legend
            self.add_to_legend(name, color, channel)

    def add_to_legend(self, name, color, channel):
        """
        Add a single entry to the legend during the network iteration.
        """
        # Create a frame for each legend entry
        legend_item = tk.Frame(self.legend_frame, bg="white")
        legend_item.pack(fill="x", padx=10, pady=5, anchor="w")

        # Color block (rectangle)
        color_block = tk.Label(
            legend_item,
            bg=rgb_to_hex(color),
            width=2,  # Fixed width for the color block
            height=1  # Fixed height for the color block
        )
        color_block.pack(side="left", padx=(0, 10))

        # SSID text with channel
        ssid_label = tk.Label(
            legend_item,
            text=f"{name} (CH {channel})",  # Include channel in the legend text
            bg="white",
            fg="black",
            font=("Arial", 10)
        )
        ssid_label.pack(side="left")

    def clear_graph_and_legend(self):
        """
        Clear the graph to show channel utilization as flat bars in real time.
        Clear legend
        """
        for trapezoid in self.trapezoids:
            trapezoid.remove()
        self.trapezoids = []

        # Clear text annotations
        for text in self.text_objects:
            text.remove()

        self.text_objects = []

        # Clear previous legend
        for widget in self.legend_frame.winfo_children():
            widget.destroy()


def configure_axis(ax):
    """
    Configures the matplotlib axis with labels, limits, and styles.
    """
    ax.set_title("WiFi Channel Utilization", color="black", fontsize=14)
    ax.set_xlabel("WiFi Channels", color="black", fontsize=12)
    ax.set_ylabel("Signal Strength (dBm)", color="black", fontsize=12)
    ax.set_xlim(1, 14)  # Channels 1-13
    ax.set_ylim(-90, -10)  # Signal between -90 and -10 dBm

    # Add ticks and labels to axes
    ax.set_xticks(range(1, 14))
    ax.set_xticklabels([str(i) for i in range(1, 14)], color="black", fontsize=10)
    ax.set_yticks(range(-90, -10, 10))
    ax.set_yticklabels([f"{i} dBm" for i in range(-90, -10, 10)], color="black", fontsize=10)

    # Set tick parameters for better visibility
    ax.tick_params(axis='x', colors='black', labelsize=10)
    ax.tick_params(axis='y', colors='black', labelsize=10)

    # Set background color for the plot area
    ax.set_facecolor("#2C2C2C")  # Dark background
    ax.grid(color="gray", linestyle="--", linewidth=0.5)


def rgb_to_hex(color):
    """
    Convert a matplotlib RGB color to a hex color code for Tkinter.
    """
    return "#%02x%02x%02x" % tuple(int(c * 255) for c in color)
