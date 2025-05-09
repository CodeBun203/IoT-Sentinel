from scapy.all import sniff, TCP, IP

def analyze_packet(packet):
    """
    Logs traffic and identifies security risks based on detected vulnerabilities.
    Args:
        packet (scapy.packet.Packet): The packet to analyze.
    """
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        print(f"[TRAFFIC] Packet detected: {src_ip}:{src_port} → {dst_ip}:{dst_port}")

        if dst_port == 23 or dst_port == 2323:
            print(f"[WARNING] Telnet detected: {src_ip} → {dst_ip}:{dst_port} (Insecure protocol)")

        if dst_port == 80 and packet[TCP].flags & 0x02:
            print(f"[INFO] HTTP SYN detected: {src_ip} → {dst_ip}:{dst_port}")

        if dst_port == 22 and packet[TCP].flags & 0x02:
            print(f"[INFO] SSH connection attempt: {src_ip} → {dst_ip}:{dst_port}")

def start_sniffing(interface="eth0", count=50):
    """
    Starts sniffing packets on the specified interface.
    Args:
        interface (str): Network interface to sniff on.
        count (int): Number of packets to capture.
    """
    print(f"[MONITOR] Starting packet sniffing on {interface}...")
    sniff(iface=interface, count=count, prn=analyze_packet)

if __name__ == "__main__":
    start_sniffing(interface="eth0", count=100)
