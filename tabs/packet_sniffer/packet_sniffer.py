import time

from scapy.layers.dot11 import Dot11
from scapy.layers.inet import IP, TCP

from scapy.all import *
import tkinter as tk
import threading

from scapy.layers.l2 import Ether


class PacketSniffer:
    def __init__(self, master):
        self.frame = tk.Frame(master, bg="#2C2C2C")

        # Scrollable text area for displaying captured packets
        self.text_frame = tk.Frame(self.frame, bg="#2C2C2C")
        self.text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.text_area = tk.Text(self.text_frame, wrap="none", bg="black", fg="white", font=("Courier", 10))
        self.text_area.pack(side="left", fill="both", expand=True)

        # Scrollbar for the text area
        self.scrollbar = tk.Scrollbar(self.text_frame, command=self.text_area.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.text_area.config(yscrollcommand=self.scrollbar.set)

        # Start/Stop Sniffing Button
        self.control_frame = tk.Frame(self.frame, bg="#2C2C2C")
        self.control_frame.pack(fill="x")
        self.start_button = tk.Button(self.control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side="left", padx=5, pady=5)
        self.stop_button = tk.Button(self.control_frame, text="Stop Sniffing", command=self.stop_sniffing, state="disabled")
        self.stop_button.pack(side="left", padx=5, pady=5)

        # Sniffing thread
        self.sniffing = False
        self.sniffer_thread = None

    def start_sniffing(self):
        """
        Start sniffing packets.
        """
        self.sniffing = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.sniffer_thread = threading.Thread(target=self.sniff_packets) # stop sniffing after closing ui
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

        # time.sleep(2)
        # packet = (
        #         IP(dst="127.0.0.1") /
        #         TCP(dport=80, sport=12345, flags="S") /  # SYN flag pentru inițiere conexiune
        #         Raw(load="GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        # )
        # send(packet)

    def stop_sniffing(self):
        """
        Stop sniffing packets.
        """
        self.sniffing = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def sniff_packets(self):
        """
        Capture packets and process them.
        """
        sniff(prn=self.process_packet, stop_filter=self.stop_filter, store=False)

    def process_packet(self, packet):
        """
        Process and display packet details in the text area.
        """
        output = "\n" + "=" * 80 + "\n"
        output += "Packet Captured:\n"

        # IEEE 802.11 Header (only if present)
        if packet.haslayer(Ether):
            output += f"IEEE 802.11 - Source MAC: {packet[Ether].src}, Destination MAC: {packet[Ether].dst}\n"

        # IP Header
        if packet.haslayer(IP):
            output += process_ip_header(packet[IP])

        # TCP Header
        if packet.haslayer(TCP):
            output += process_tcp_header(packet[TCP], packet)

        # Append packet details to the text area
        self.text_area.insert(tk.END, output)
        self.text_area.see(tk.END)  # Auto-scroll to the bottom

    def stop_filter(self, packet):
        """
        Stop filter for sniffing.
        """
        return not self.sniffing


def process_ip_header(ip_layer):
    """
    Process and format the IP header details.

    Parameters:
        ip_layer (IP): The IP layer of the packet.

    Returns:
        str: A formatted string containing the IP header details.

    IP Header Fields:
    - version: Version of the IP protocol (4 for IPv4, 6 for IPv6).
    - ihl: Internet Header Length, specifying the size of the IP header in 32-bit words.
    - tos: Type of Service, indicating the quality of service for the packet.
    - len: Total length of the IP packet, including header and data (in bytes).
    - id: Identification field, used for fragment reassembly.
    - flags: Control flags (e.g., DF = Don't Fragment, MF = More Fragments).
    - frag: Fragment offset, indicating the position of this fragment in the original datagram.
    - ttl: Time to Live, limiting the packet's lifetime (in hops).
    - proto: Protocol used in the data portion of the IP datagram (e.g., TCP, UDP, ICMP).
    - chksum: Checksum of the IP header for error-checking.
    - src: Source IP address (already displayed separately).
    - dst: Destination IP address (already displayed separately).
    - options: IP options, if any (rarely used).
    """
    output = f"IP - Source: {ip_layer.src}, Destination: {ip_layer.dst}\n"  # Highlight source and destination
    output += "IP Header Details:\n"

    for field in ip_layer.fields_desc:
        field_name = field.name
        if field_name in ["src", "dst"]:  # Skip already displayed fields
            continue
        field_value = ip_layer.getfieldval(field_name)
        if field_name == 'proto':  # Convert protocol number to its name
            field_value = IP_PROTOS[field_value]
        output += f"  {field_name}: {field_value}\n"

    return output

def process_tcp_header(tcp_layer, packet):
    """
    Extracts details from the TCP header of a packet and formats it into a readable string.

    TCP Header Fields:
    - `seq`: Sequence number of the first byte in the segment's data payload.
    - `ack`: Acknowledgment number of the next expected sequence.
    - `dataofs`: Header length in 32-bit words.
    - `reserved`: Reserved for future use (currently set to 0).
    - `flags`: Control flags for managing the connection (e.g., SYN, ACK, FIN).
    - `window`: Window size indicating the sender's receive buffer.
    - `chksum`: Checksum for error-checking.
    - `urgptr`: Urgent pointer indicating the end of urgent data (if applicable).
    - `options`: Additional parameters such as MSS or window scaling.

    Args:
        packet (scapy.Packet): The captured packet.

    Returns:
        str: Formatted string containing TCP header details.
    """
    output = f"TCP - Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}\n"  # Highlight ports
    output += "TCP Header Details:\n"
    for field in tcp_layer.fields_desc:
        field_name = field.name
        if field_name in ["sport", "dport"]:  # Skip already displayed fields
            continue
        field_value = tcp_layer.getfieldval(field_name)
        output += f"  {field_name}: {field_value}\n"

    # HTTP Payload (if destination port is 80)
    if tcp_layer.dport == 80 and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")  # Decode payload as ASCII
        output += f"HTTP Payload:\n{payload}\n"

    return output
