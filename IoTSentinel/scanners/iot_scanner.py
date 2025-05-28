# /home/mininet/IoTSentinel/scanners/iot_scanner.py
import socket
import json
import sys
import os

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
    
    # Read target IPs from command line arguments
    target_ips_to_scan = []
    if len(sys.argv) > 1:
        target_ips_to_scan = sys.argv[1:] # All arguments after script name are IPs
    else:
        print("[iot_scanner_stderr] No target IPs provided to iot_scanner.py. Exiting.", file=sys.stderr)
        # Output a status message if no IPs are provided
        print(json.dumps({
            "scanner": "iot_port_scanner", 
            "status": "scan_skipped_no_target_ips_provided"
        }))
        sys.exit(0)

    print(f"[iot_scanner_stderr] Will scan IPs: {target_ips_to_scan}", file=sys.stderr)

    for device_ip in target_ips_to_scan:
        ports_to_scan_for_ip = DEFAULT_PORTS_TO_SCAN # Or make this configurable per IP if needed

        if not ports_to_scan_for_ip: 
            print(f"[iot_scanner_stderr] No ports defined for scanning on {device_ip}, skipping.", file=sys.stderr)
            continue

        open_ports = scan_open_ports(device_ip, ports_to_scan_for_ip)
        if open_ports:
            severity = "medium" 
            vuln_type_name = "open_ports"
            details_message = f"Device {device_ip} has open port(s): {open_ports}."

            if 23 in open_ports: 
                severity = "high" # Telnet is higher risk
                vuln_type_name = "open_telnet_port"
                details_message = f"Device {device_ip} has a high-risk open Telnet port: 23. Other open: {open_ports}."
            # Add more specific checks if needed (e.g., for SSH port 22)
            
            vuln_details = {
                "scanner": "iot_port_scanner", "ip": device_ip,
                "vulnerability": vuln_type_name, "ports": open_ports,
                "details": details_message, "severity": severity
            }
            print(json.dumps(vuln_details)) # Output JSON for POX
            results_found_this_run.append(vuln_details)

    if not results_found_this_run and target_ips_to_scan: # Only print this if IPs were scanned
        print(json.dumps({
            "scanner": "iot_port_scanner", 
            "status": "scan_complete_no_target_ports_found_on_scanned_ips", 
            "targets_checked": target_ips_to_scan # Report which IPs were actually checked
        }))
        print("[iot_scanner_stderr] No scannable open ports found on any target IPs during this run.", file=sys.stderr)
    
    print("[iot_scanner_stderr] iot_scanner.py scan finished.", file=sys.stderr)
