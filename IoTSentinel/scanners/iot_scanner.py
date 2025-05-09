import os
import socket

def scan_open_ports(ip, ports=[23, 80, 443, 22]):
    """Scans a device for open ports."""
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    return open_ports

device_ip = "10.0.0.1"
open_ports = scan_open_ports(device_ip)

if open_ports:
    print(f"[VULNERABILITY] Device {device_ip} has open ports: {open_ports}")
else:
    print(f"[SECURE] No open ports detected on {device_ip}")
