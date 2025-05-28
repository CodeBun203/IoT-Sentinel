# /home/mininet/IoTSentinel/scanners/ssh_scanner.py
import paramiko
import json
import socket
import sys
import os

# Path to devices.config
DEVICES_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "devices.config")

# Default weak credentials to try, in addition to those from devices.config
# Ensure 'user':'password' is here if you want to test the fix for it on h3.
WEAK_CREDS = [
    ("user", "password"),      # Matches the one set up in iot_topo.py for h3
    ("mininet", "mininet"),
    ("root", "root")
]

def load_credentials_from_devices_config(config_path):
    """
    Loads credentials from the devices.config JSON file.
    Attempts to parse user:pass and user/pass formats from 'basic' auth entries.
    """
    additional_creds = []
    try:
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        for device_name, device_info in config_data.items():
            auth_details = device_info.get("auth")
            if auth_details and isinstance(auth_details, list):
                auth_type = auth_details[0]
                if auth_type == "basic" and len(auth_details) > 1:
                    creds_str = auth_details[1]
                    user, passwd = None, None
                    if isinstance(creds_str, str) and creds_str:
                        if ':' in creds_str:
                            user, _, passwd = creds_str.partition(':')
                        elif '/' in creds_str:
                            user, _, passwd = creds_str.partition('/')
                        else:
                            user = creds_str
                            passwd = ""
                        
                        if user:
                            passwd = passwd if passwd is not None else ""
                            if (user, passwd) not in additional_creds:
                                additional_creds.append((user, passwd))
                                print(f"[ssh_scanner_stderr] Loaded SSH cred from devices.config: {user}:{'********' if passwd else '(empty)'} (for device type: {device_name})", file=sys.stderr)
    except FileNotFoundError:
        print(f"[ssh_scanner_stderr] WARNING: devices.config not found at {config_path}", file=sys.stderr)
    except json.JSONDecodeError:
        print(f"[ssh_scanner_stderr] WARNING: Could not decode JSON from devices.config at {config_path}", file=sys.stderr)
    except Exception as e:
        print(f"[ssh_scanner_stderr] WARNING: Error loading credentials from {config_path}: {e}", file=sys.stderr)
    return additional_creds

# MODIFIED: Slightly increased timeout for reachability check
def is_reachable(ip, port=22, timeout=3.0): # Increased timeout
    """Checks if an IP and port are reachable."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return True
        else:
            return False
    except socket.timeout:
        return False
    except socket.error:
        return False
    except Exception:
        return False

def check_weak_ssh_credentials(ip, username, password_to_try):
    """Attempts to log in via SSH with given credentials."""
    print(f"[ssh_scanner_stderr] Attempting SSH to {ip} with {username}:{'********' if password_to_try else '(empty password)'}", file=sys.stderr)
    ssh_client = None
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(ip, username=username, password=password_to_try, 
                           timeout=10, banner_timeout=15, auth_timeout=15,
                           allow_agent=False, look_for_keys=False)
        
        print(f"[ssh_scanner_stderr] SUCCESSFUL weak SSH login to {ip} with {username}:{'********' if password_to_try else '(empty password)'}", file=sys.stderr)
        
        vuln_details_for_pox = {
            "scanner": "ssh_weak_creds_scanner",
            "ip": ip,
            "vulnerability": "weak_ssh_credentials",
            "port": 22, 
            "username": username,
            "found_password": password_to_try,
            "details": f"Weak SSH credentials confirmed for user '{username}' on {ip}.",
            "severity": "high" 
        }
        print(json.dumps(vuln_details_for_pox))
        return True
    except paramiko.AuthenticationException:
        print(f"[ssh_scanner_stderr] Authentication FAILED for {ip} with {username}:{'********' if password_to_try else '(empty password)'}", file=sys.stderr)
    except paramiko.SSHException as e: 
        print(f"[ssh_scanner_stderr] SSHException for {ip} with {username}:{'********' if password_to_try else '(empty password)'} - {e}", file=sys.stderr)
    except socket.timeout: 
        print(f"[ssh_scanner_stderr] Socket timeout during Paramiko connect to {ip} for user {username}", file=sys.stderr)
    except Exception as e: 
        print(f"[ssh_scanner_stderr] Generic Exception during SSH attempt for {ip} with {username}:{'********' if password_to_try else '(empty password)'} - {e}", file=sys.stderr)
    finally:
        if ssh_client:
            ssh_client.close()
    return False

if __name__ == "__main__":
    print("[ssh_scanner_stderr] ssh_scanner.py started.", file=sys.stderr)
    found_any_weakness_this_run = False
    
    # Read target IPs from command line arguments
    target_ips_for_scan = []
    if len(sys.argv) > 1:
        target_ips_for_scan = sys.argv[1:]
    else:
        print("[ssh_scanner_stderr] No target IPs provided to ssh_scanner.py. Exiting.", file=sys.stderr)
        print(json.dumps({
            "scanner": "ssh_weak_creds_scanner", 
            "status": "scan_skipped_no_target_ips_provided"
        }))
        sys.exit(0)
        
    print(f"[ssh_scanner_stderr] Will scan IPs for weak SSH: {target_ips_for_scan}", file=sys.stderr)

    all_creds_to_try = list(WEAK_CREDS) 
    creds_from_config = load_credentials_from_devices_config(DEVICES_CONFIG_PATH)
    for cred_pair in creds_from_config:
        if cred_pair not in all_creds_to_try: all_creds_to_try.append(cred_pair)
    print(f"[ssh_scanner_stderr] Combined credentials to try: {len(all_creds_to_try)} pairs.", file=sys.stderr)

    for device_ip in target_ips_for_scan: 
        if not is_reachable(device_ip, port=22): 
            print(f"[ssh_scanner_stderr] Target {device_ip}:22 unreachable by pre-check, skipping.", file=sys.stderr)
            continue
        print(f"[ssh_scanner_stderr] Target {device_ip}:22 reachable. Checking credentials.", file=sys.stderr)
        for uname, passwd in all_creds_to_try:
            if check_weak_ssh_credentials(device_ip, uname, passwd): 
                found_any_weakness_this_run = True
                # break # Optional: stop after first success per host
    
    if not found_any_weakness_this_run and target_ips_for_scan:
        print(json.dumps({
            "scanner": "ssh_weak_creds_scanner", 
            "status": "scan_complete_no_weak_creds_found_on_reachable_ssh_targets", 
            "targets_checked": target_ips_for_scan
        }))
        print("[ssh_scanner_stderr] No weak SSH credentials found on targeted IPs with reachable SSH.", file=sys.stderr)
    
    print("[ssh_scanner_stderr] ssh_scanner.py scan finished.", file=sys.stderr)
