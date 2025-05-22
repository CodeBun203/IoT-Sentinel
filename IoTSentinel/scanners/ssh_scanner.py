# /home/mininet/IoTSentinel/scanners/ssh_scanner.py
import paramiko
import json
import socket
import sys
import os

# Path to devices.config
DEVICES_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "devices.config")

# Target IPs for SSH scanning. Customize as needed.
TARGET_IPS_FOR_SSH_SCAN = ["10.0.0.3"] 

# Default weak credentials to try, in addition to those from devices.config
# Ensure 'user':'password' is here if you want to test the fix for it on h3.
WEAK_CREDS = [
    ("user", "password"),      # Matches the one set up in iot_topo.py for h3
    ("mininet", "mininet"),    # Common Mininet default, will be changed by fixer if found
    ("root", "root")           # Common default
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
                # We are interested in 'basic' auth for SSH username/password
                if auth_type == "basic" and len(auth_details) > 1:
                    creds_str = auth_details[1]
                    user, passwd = None, None # Initialize
                    if isinstance(creds_str, str) and creds_str: # Ensure creds_str is a non-empty string
                        if ':' in creds_str:
                            user, _, passwd = creds_str.partition(':')
                        elif '/' in creds_str: # Handle user/pass format
                            user, _, passwd = creds_str.partition('/')
                        else: # Assume it's a username with an implied empty password if no delimiter
                            user = creds_str
                            passwd = "" # Explicitly set empty password
                        
                        if user: # User part must be present
                            passwd = passwd if passwd is not None else "" # Ensure passwd is a string
                            if (user, passwd) not in additional_creds: # Avoid duplicates
                                additional_creds.append((user, passwd))
                                print(f"[ssh_scanner_stderr] Loaded SSH cred from devices.config: {user}:{'********' if passwd else '(empty)'} (for device type: {device_name})", file=sys.stderr)
    except FileNotFoundError:
        print(f"[ssh_scanner_stderr] WARNING: devices.config not found at {config_path}", file=sys.stderr)
    except json.JSONDecodeError:
        print(f"[ssh_scanner_stderr] WARNING: Could not decode JSON from devices.config at {config_path}", file=sys.stderr)
    except Exception as e:
        print(f"[ssh_scanner_stderr] WARNING: Error loading credentials from {config_path}: {e}", file=sys.stderr)
    return additional_creds

def is_reachable(ip, port=22, timeout=2.0): # Reduced timeout for faster scans
    """Checks if an IP and port are reachable."""
    # print(f"[ssh_scanner_stderr] Checking reachability for {ip}:{port} with timeout {timeout}s", file=sys.stderr) # Can be verbose
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            # print(f"[ssh_scanner_stderr] {ip}:{port} IS reachable.", file=sys.stderr)
            return True
        else:
            # print(f"[ssh_scanner_stderr] {ip}:{port} is NOT reachable (connect_ex code: {result}).", file=sys.stderr)
            return False
    except socket.timeout:
        # print(f"[ssh_scanner_stderr] Socket timeout checking reachability for {ip}:{port}.", file=sys.stderr)
        return False
    except socket.error: # Catches other socket errors like Connection Refused
        # print(f"[ssh_scanner_stderr] Socket error checking reachability for {ip}:{port} - {e}", file=sys.stderr)
        return False
    except Exception: # More general exception
        # print(f"[ssh_scanner_stderr] Generic error checking reachability for {ip}:{port} - {e}", file=sys.stderr)
        return False

def check_weak_ssh_credentials(ip, username, password_to_try):
    """Attempts to log in via SSH with given credentials."""
    print(f"[ssh_scanner_stderr] Attempting SSH to {ip} with {username}:{'********' if password_to_try else '(empty password)'}", file=sys.stderr)
    ssh_client = None
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Adjust timeouts as needed; shorter for faster scanning, longer for slow devices/networks
        ssh_client.connect(ip, username=username, password=password_to_try, 
                           timeout=10, banner_timeout=15, auth_timeout=15,
                           allow_agent=False, look_for_keys=False)
        
        print(f"[ssh_scanner_stderr] SUCCESSFUL weak SSH login to {ip} with {username}:{'********' if password_to_try else '(empty password)'}", file=sys.stderr)
        
        vuln_details_for_pox = {
            "scanner": "ssh_weak_creds_scanner",
            "ip": ip,
            "vulnerability": "weak_ssh_credentials",
            "port": 22, # Standard SSH port
            "username": username,
            "found_password": password_to_try, # Pass the actual password for the fixer
            "details": f"Weak SSH credentials confirmed for user '{username}' on {ip}.",
            "severity": "high" 
        }
        print(json.dumps(vuln_details_for_pox)) # Output for POX to process
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
    
    # Combine default weak creds with those from devices.config
    all_creds_to_try = list(WEAK_CREDS) 
    creds_from_config = load_credentials_from_devices_config(DEVICES_CONFIG_PATH)
    
    for cred_pair in creds_from_config:
        if cred_pair not in all_creds_to_try: # Avoid duplicates
            all_creds_to_try.append(cred_pair)
    
    print(f"[ssh_scanner_stderr] Combined credentials to try: {len(all_creds_to_try)} pairs.", file=sys.stderr)

    for device_ip in TARGET_IPS_FOR_SSH_SCAN: 
        if not is_reachable(device_ip, port=22): 
            print(f"[ssh_scanner_stderr] Target {device_ip}:22 determined unreachable by pre-check, skipping credential scan for this IP.", file=sys.stderr)
            continue # Skip to the next IP if SSH port is not even open/reachable
        
        print(f"[ssh_scanner_stderr] Target {device_ip}:22 is reachable. Proceeding with credential checks.", file=sys.stderr)
        # Iterate through all credentials for the current reachable IP
        for uname, passwd in all_creds_to_try:
            if check_weak_ssh_credentials(device_ip, uname, passwd): 
                found_any_weakness_this_run = True
                # If you only want to report/fix ONE weak credential per host per scan run,
                # you could 'break' here to move to the next IP.
                # For now, it will report all weak creds it finds on a host.
    
    if not found_any_weakness_this_run:
        # This status message is sent if no vulnerabilities were printed as JSON
        print(json.dumps({
            "scanner": "ssh_weak_creds_scanner", 
            "status": "scan_complete_no_specific_weak_creds_found_or_targets_unreachable", 
            "targets_checked": TARGET_IPS_FOR_SSH_SCAN
        }))
        print("[ssh_scanner_stderr] No weak SSH credentials (from combined list) found on targeted IPs, OR targets/ports were unreachable by pre-check.", file=sys.stderr)
    
    print("[ssh_scanner_stderr] ssh_scanner.py scan finished.", file=sys.stderr)
