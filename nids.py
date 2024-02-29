import scapy.all as scapy
from datetime import datetime

class NIDS:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.external_agents = set()

    def start_sniffing(self, filter_protocol=None):
        try:
            print("[*] Starting the Network Intrusion Detection System...")
            scapy.sniff(iface=self.interface, store=False, prn=self.process_packet, filter=filter_protocol)
        except KeyboardInterrupt:
            print("[-] User interrupted the program.")
            self.log_event("User interrupted the program.")

    def process_packet(self, packet):
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            print(f"[*] {timestamp} - Detected IP packet from {ip_src} to {ip_dst}")

            if ip_src not in self.internal_ips():
                self.external_agents.add(ip_src)

            if ip_dst not in self.internal_ips():
                self.external_agents.add(ip_dst)

            if packet.haslayer(scapy.TCP):
                self.process_tcp(packet)

            elif packet.haslayer(scapy.UDP):
                self.process_udp(packet)

            else:
                print("[+] Non-TCP/UDP traffic detected")
                self.log_event("Non-TCP/UDP traffic detected", timestamp)

    def process_tcp(self, packet):
        tcp_src_port = packet[scapy.TCP].sport
        tcp_dst_port = packet[scapy.TCP].dport
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"[+] {timestamp} - TCP Packet - Source Port: {tcp_src_port}, Destination Port: {tcp_dst_port}")
        self.log_event(f"TCP Packet - Source Port: {tcp_src_port}, Destination Port: {tcp_dst_port}", timestamp)

        if tcp_dst_port == 80:  # Check for HTTP traffic
            print("[+] Possible HTTP traffic detected")
            self.log_event("Possible HTTP traffic detected", timestamp)

        elif tcp_dst_port == 443:  # Check for HTTPS traffic
            print("[+] Possible HTTPS traffic detected")
            self.log_event("Possible HTTPS traffic detected", timestamp)

        else:
            print("[+] Other TCP traffic detected")

    def process_udp(self, packet):
        udp_src_port = packet[scapy.UDP].sport
        udp_dst_port = packet[scapy.UDP].dport
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"[+] {timestamp} - UDP Packet - Source Port: {udp_src_port}, Destination Port: {udp_dst_port}")
        self.log_event(f"UDP Packet - Source Port: {udp_src_port}, Destination Port: {udp_dst_port}", timestamp)

        # Add more UDP-specific checks here if needed

    def log_event(self, message, timestamp):
        with open("nids_log.txt", "a") as log_file:
            log_file.write(f"{timestamp} - {message}\n")

    def internal_ips(self):
        # Define your internal IP address range(s)
        internal_ranges = ["192.168.1.0/24", "10.0.0.0/8"]  # Add more as needed

        internal_ips = set()
        for ip_range in internal_ranges:
            internal_ips.update(scapy.utils.ltoa(ip) for ip in scapy.utils.iprange(ip_range))

        return internal_ips

    def monitor_external_agents(self):
        print("[+] Monitoring External Agents:")
        for agent in self.external_agents:
            print(f"    - {agent}")

def main():
    nids = NIDS(interface="eth0")
    nids.start_sniffing(filter_protocol="ip")
    nids.monitor_external_agents()

if __name__ == "__main__":
    main()
