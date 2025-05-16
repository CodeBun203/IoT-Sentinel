import paramiko
import json
import socket
import sys

TARGET_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.100"]
# Ensure user:password is the one set on h3
WEAK_CREDS = [("user", "password"), ("mininet", "mininet"), ("root", "root")] 

def is_reachable(ip, port=22, timeout=1.0):
    print(f"[ssh_scanner_stderr] Checking reachability for {ip}:{port}", file=sys.stderr)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            print(f"[ssh_scanner_stderr] {ip}:{port} is reachable.", file=sys.stderr)
            return True
        else:
            print(f"[ssh_scanner_stderr] {ip}:{port} is NOT reachable (connect_ex code: {result}).", file=sys.stderr)
            return False
    except socket.error as e:
        print(f"[ssh_scanner_stderr] Socket error checking reachability for {ip}:{port} - {e}", file=sys.stderr)
        return False

def check_weak_ssh_credentials(ip, username, password):
    print(f"[ssh_scanner_stderr] Attempting SSH to {ip} with {username}:{'*' * len(password)}", file=sys.stderr)
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10, allow_agent=False, look_for_keys=False, banner_timeout=20, auth_timeout=20)
        
        print(f"[ssh_scanner_stderr] SUCCESSFUL weak SSH login to {ip} with {username}", file=sys.stderr)
        vuln_details = {
            "scanner": "ssh_weak_creds_scanner",
            "ip": ip,
            "vulnerability": "weak_ssh",
            "port": 22,
            "username": username,
            "details": f"Weak SSH credentials ({username}:***) on {ip}.",
            "severity": "high"
        }
        print(json.dumps(vuln_details)) # STDOUT
        ssh.close()
        return True
    except paramiko.AuthenticationException:
        print(f"[ssh_scanner_stderr] Authentication failed for {ip} with {username}", file=sys.stderr)
    except paramiko.SSHException as e: # More specific SSH errors
        print(f"[ssh_scanner_stderr] SSHException for {ip} with {username}: {e}", file=sys.stderr)
    except socket.timeout:
        print(f"[ssh_scanner_stderr] Socket timeout connecting to {ip} for SSH with {username}", file=sys.stderr)
    except Exception as e: # Generic catch-all
        print(f"[ssh_scanner_stderr] Generic Exception for {ip} with {username}: {e}", file=sys.stderr)
    return False

if __name__ == "__main__":
    print("[ssh_scanner_stderr] ssh_scanner.py started.", file=sys.stderr)
    found_any_weakness = False
    # Focus scan on h3 for this test
    ips_to_ssh_scan = [h_ip for h_ip in TARGET_IPS if h_ip == "10.0.0.3"] 

    for device_ip in ips_to_ssh_scan:
        if not is_reachable(device_ip, port=22):
            print(f"[ssh_scanner_stderr] Target {device_ip}:22 is not reachable by scanner, skipping credential check.", file=sys.stderr)
            continue
        
        print(f"[ssh_scanner_stderr] Target {device_ip}:22 is reachable, proceeding with credential checks.", file=sys.stderr)
        for username, password in WEAK_CREDS:
            if check_weak_ssh_credentials(device_ip, username, password):
                found_any_weakness = True
                # break # Stop after first success for this IP
    
    if not found_any_weakness:
        # IMPORTANT: Print a status to stdout even if nothing is found
        print(json.dumps({"scanner": "ssh_weak_creds_scanner", "status": "scan_complete_no_weak_creds_found_or_unreachable", "targets_checked": ips_to_ssh_scan}))
        print("[ssh_scanner_stderr] No weak SSH credentials found on targeted IPs OR targets were unreachable.", file=sys.stderr)
    
    print("[ssh_scanner_stderr] ssh_scanner.py scan finished.", file=sys.stderr)
