# /home/mininet/IoTSentinel/scanners/iot_scanner.py
import socket
import json
import sys
import os

TARGET_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.100"]
DEFAULT_PORTS_TO_SCAN = [22, 23, 80, 1883, 443, 8080]

def scan_open_ports(ip, ports_to_scan):
    open_ports_found = []
    print(f"[iot_scanner_stderr] Attempting to scan IP: {ip} for ports: {ports_to_scan}", file=sys.stderr)
    for port in ports_to_scan:
        print(f"[iot_scanner_stderr] Trying {ip}:{port}", file=sys.stderr)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0) 
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"[iot_scanner_stderr] Port {port} is OPEN on {ip}", file=sys.stderr)
                open_ports_found.append(port)
            sock.close()
        except socket.error as e:
            print(f"[iot_scanner_stderr] Socket error for {ip}:{port} - {e}", file=sys.stderr)
        except Exception as e: 
            print(f"[iot_scanner_stderr] Generic error for {ip}:{port} - {e}", file=sys.stderr)
    return open_ports_found

if __name__ == "__main__":
    print("[iot_scanner_stderr] iot_scanner.py started.", file=sys.stderr)
    results_found_this_run = []
    
    for device_ip in TARGET_IPS:
        ports_to_scan_for_ip = DEFAULT_PORTS_TO_SCAN

        if not ports_to_scan_for_ip: 
            print(f"[iot_scanner_stderr] No ports defined for scanning on {device_ip}, skipping.", file=sys.stderr)
            continue

        open_ports = scan_open_ports(device_ip, ports_to_scan_for_ip)
        if open_ports:
            severity = "medium" 
            vuln_type_name = "open_ports" # Generic name
            details_message = f"Device {device_ip} has open port(s): {open_ports}."

            if 23 in open_ports: 
                severity = "high"
                vuln_type_name = "open_telnet_port" # More specific
                details_message = f"Device {device_ip} has a high-risk open Telnet port: 23. Other open ports: {open_ports}."
            elif 22 in open_ports and not any(p in [23] for p in open_ports): # If SSH is open but not Telnet
                 severity = "medium" # Open SSH isn't critical alone, weak creds make it so.
                 # Keep vuln_type_name as "open_ports" or be more specific if desired
            
            vuln_details = {
                "scanner": "iot_port_scanner",
                "ip": device_ip,
                "vulnerability": vuln_type_name, 
                "ports": open_ports,
                "details": details_message,
                "severity": severity
            }
            print(json.dumps(vuln_details))
            results_found_this_run.append(vuln_details)

    if not results_found_this_run:
        print(json.dumps({
            "scanner": "iot_port_scanner", 
            "status": "scan_complete_no_target_ports_found_or_reachable_for_defined_scans", 
            "targets_checked": TARGET_IPS
        }))
        print("[iot_scanner_stderr] No scannable open ports (as defined) found on any target IPs during this run.", file=sys.stderr)
    
    print("[iot_scanner_stderr] iot_scanner.py scan finished.", file=sys.stderr)

