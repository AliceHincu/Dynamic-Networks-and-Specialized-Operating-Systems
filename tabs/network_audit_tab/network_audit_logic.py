import time
import threading

import psutil
import requests
from scapy.all import sniff
from scapy.layers.inet import TCP, IP, UDP

# COMMON_PORTS = {
#     80: "HTTP",
#     443: "HTTPS",
#     22: "SSH",
#     21: "FTP",
#     25: "SMTP",
#     110: "POP3",
#     143: "IMAP",
#     53: "DNS",
#     123: "NTP",
#     161: "SNMP",
#     3306: "MySQL",
#     1433: "MSSQL",
#     3389: "RDP",
#     6379: "Redis",
#     5432: "PostgreSQL",
# }
class NetworkAuditLogic:
    def __init__(self):
        self.traffic_data = {}  # Store traffic data for each connection
        self.lock = threading.Lock()  # Lock for thread-safe access to traffic_data
        self.sniffing_thread = None
        self.stop_sniffing_event = threading.Event()
        self.last_active_time = {}  # Track the last activity time for each connection
        self.location_cache = {}  # Cache for storing location results
        self.application_cache = {}  # Cache for storing application names by PID


    def start_sniffing(self):
        """Start packet sniffing in a separate thread."""
        self.sniffing_thread = threading.Thread(target=self.sniff_packets)
        self.sniffing_thread.daemon = True
        self.sniffing_thread.start()

    def stop_sniffing(self):
        """Stop packet sniffing."""
        self.stop_sniffing_event.set()
        if self.sniffing_thread:
            self.sniffing_thread.join()

    def sniff_packets(self):
        """Capture packets and process them."""
        sniff(
            prn=self.process_packet,
            filter="tcp or udp",  # Capture only TCP/UDP packets
            store=False,
            stop_filter=lambda _: self.stop_sniffing_event.is_set(),
        )

    def process_packet(self, packet):
        """Process captured packets and update traffic data."""
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dest_ip = ip_layer.dst
            src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else "unknown")
            dest_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else "unknown")
            protocol = "TCP" if TCP in packet else "UDP"
            key = f"{src_ip}:{src_port} -> {dest_ip}:{dest_port}"

            with self.lock:  # Ensure thread-safe access
                if key not in self.traffic_data:
                    # try:
                    #     dns_name = socket.gethostbyaddr(dest_ip)[0]
                    # except socket.herror:
                    #     dns_name = "Unknown"

                    # port_type = COMMON_PORTS.get(dest_port, "Unknown")
                    # dns_name = "Not activated"
                    # self.traffic_data[key] = {"time": [], "bps": [], "dns_name": dns_name,
                    # "port_type": port_type}
                    self.traffic_data[key] = {"time": [], "bps": [], "protocol": protocol}

                packet_size = len(packet)
                current_time = int(time.time())
                self.last_active_time[key] = current_time

                # Update traffic data
                # If it's the same packet, add also the new packet
                if self.traffic_data[key]["time"] and self.traffic_data[key]["time"][-1] == current_time:
                    self.traffic_data[key]["bps"][-1] += packet_size * 8  # Adaugă dimensiunea în biți
                else:
                    # Add new entry
                    self.traffic_data[key]["time"].append(current_time)
                    self.traffic_data[key]["bps"].append(packet_size * 8)  # Convert bytes to bits

                # Keep only the last 60 seconds of data
                if len(self.traffic_data[key]["time"]) > 60:
                    self.traffic_data[key]["time"].pop(0)
                    self.traffic_data[key]["bps"].pop(0)

    def get_traffic_data(self):
        """Get a thread-safe copy of traffic data."""
        with self.lock:
            return dict(self.traffic_data)

    def add_zero_traffic(self):
        """Add zero traffic for connections with no packets in the last second and remove inactive connections."""
        current_time = time.time()
        keys_to_remove = []

        with self.lock:
            for key, last_time in self.last_active_time.items():
                if current_time - last_time > 15:  # Remove if inactive for 15 seconds
                    keys_to_remove.append(key)
                elif self.traffic_data[key]["time"] and (current_time - self.traffic_data[key]["time"][-1] > 1):
                    # Append 0 traffic if no updates in the last second
                    self.traffic_data[key]["time"].append(current_time)
                    self.traffic_data[key]["bps"].append(0)

            # Remove inactive connections
            for key in keys_to_remove:
                del self.traffic_data[key]
                del self.last_active_time[key]

    def resolve_location(self, ip):
        """Resolve geolocation information for an IP address."""
        if ip in self.location_cache:
            return self.location_cache[ip]

        # Check if the IP is private or broadcast
        if is_private_or_broadcast(ip):
            self.location_cache[ip] = "Local Network"
            return "Local Network"

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
        return location

    def get_application_name(self, src_ip, src_port, dest_ip, dest_port):
        """Get the application name for a specific connection."""
        try:
            # Iterate over all connections to find the matching one
            for conn in psutil.net_connections(kind="inet"):
                if (conn.laddr.ip == src_ip and conn.laddr.port == src_port and
                        conn.raddr.ip == dest_ip and conn.raddr.port == dest_port):
                    pid = conn.pid
                    if pid:
                        # Check if the application is already cached
                        if pid in self.application_cache:
                            return self.application_cache[pid]

                        # Otherwise, fetch the application name and cache it
                        proc = psutil.Process(pid)
                        app_name = proc.name()
                        self.application_cache[pid] = app_name
                        return app_name

            # Handle special cases for local or broadcast traffic
            if dest_ip == "255.255.255.255":
                return "Broadcast Traffic"
            if src_ip == "0.0.0.0" or dest_ip == "0.0.0.0":
                return "Local Traffic"
            if src_ip.startswith("127.") or dest_ip.startswith("127."):
                return "Loopback Traffic"
            return "Unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "Unknown"


import ipaddress

def is_private_or_broadcast(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_loopback
    except ValueError:
        return False
