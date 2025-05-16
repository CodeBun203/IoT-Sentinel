import netifaces as ni
from scapy.all import sniff, TCP, IP

def get_mininet_interfaces():
    """Retrieve Mininet host interfaces dynamically."""
    interfaces = ni.interfaces()
    return [iface for iface in interfaces if "-eth0" in iface]  # Filters only Mininet host interfaces

def analyze_packet(packet):
    """Logs traffic and identifies security risks based on detected vulnerabilities."""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        log_entry = f"[TRAFFIC] Packet detected: {src_ip}:{src_port} → {dst_ip}:{dst_port}\n"

        if dst_port == 23 or dst_port == 2323:
            log_entry += f"[WARNING] Telnet detected: {src_ip} → {dst_ip}:{dst_port} (Insecure protocol)\n"

        if dst_port == 80 and packet[TCP].flags & 0x02:
            log_entry += f"[INFO] HTTP SYN detected: {src_ip} → {dst_ip}:{dst_port}\n"

        if dst_port == 22 and packet[TCP].flags & 0x02:
            log_entry += f"[INFO] SSH connection attempt: {src_ip} → {dst_ip}:{dst_port}\n"

        # Log detected vulnerabilities to POX for ACL updates
        with open("/home/mininet/IoTSentinel/logs/packet_logs.txt", "a") as log_file:
            log_file.write(log_entry)

        print(log_entry.strip())  # Print for debugging

def start_sniffing(interface, count=50):
    """Starts sniffing packets on the specified interface."""
    print(f"[MONITOR] Starting packet sniffing on {interface}...")
    sniff(iface=interface, count=count, prn=analyze_packet)

if __name__ == "__main__":
    # Select Mininet host interfaces dynamically
    mininet_interfaces = get_mininet_interfaces()
    for interface in mininet_interfaces:
        start_sniffing(interface, count=100)
