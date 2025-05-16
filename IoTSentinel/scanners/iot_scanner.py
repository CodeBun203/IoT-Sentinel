import socket
import json
import sys

TARGET_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.100"]
PORTS_TO_SCAN = [22, 23, 80, 1883, 443, 8080]

def scan_open_ports(ip, ports_to_scan):
    open_ports_found = []
    print(f"[iot_scanner_stderr] Attempting to scan IP: {ip} for ports: {ports_to_scan}", file=sys.stderr)
    for port in ports_to_scan:
        print(f"[iot_scanner_stderr] Trying {ip}:{port}", file=sys.stderr)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"[iot_scanner_stderr] Port {port} is OPEN on {ip}", file=sys.stderr)
                open_ports_found.append(port)
            sock.close()
        except socket.error as e:
            print(f"[iot_scanner_stderr] Socket error for {ip}:{port} - {e}", file=sys.stderr)
    return open_ports_found

if __name__ == "__main__":
    print("[iot_scanner_stderr] iot_scanner.py started.", file=sys.stderr)
    results_found_this_run = []
    for device_ip in TARGET_IPS:
        open_ports = scan_open_ports(device_ip, PORTS_TO_SCAN)
        if open_ports:
            severity = "medium"
            if 23 in open_ports: severity = "high"
            
            vuln_details = {
                "scanner": "iot_port_scanner",
                "ip": device_ip,
                "vulnerability": "open_ports",
                "ports": open_ports,
                "details": f"Device {device_ip} has open ports: {open_ports}.",
                "severity": severity
            }
            print(json.dumps(vuln_details)) # STDOUT
            results_found_this_run.append(vuln_details)

    if not results_found_this_run:
        # IMPORTANT: Print a status to stdout even if nothing is found
        print(json.dumps({"scanner": "iot_port_scanner", "status": "scan_complete_no_target_ports_found_or_reachable", "targets_checked": TARGET_IPS}))
        print("[iot_scanner_stderr] No scannable open ports found on any target IPs during this run.", file=sys.stderr)
    
    print("[iot_scanner_stderr] iot_scanner.py scan finished.", file=sys.stderr)
