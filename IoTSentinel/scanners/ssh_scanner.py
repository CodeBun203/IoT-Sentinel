# /home/mininet/IoTSentinel/scanners/ssh_scanner.py
import paramiko
import json
import socket
import sys
import os

TARGET_IPS_FOR_SSH_SCAN = ["10.0.0.3"] 
WEAK_CREDS = [("user", "password"), ("mininet", "mininet"), ("root", "root")] 

def is_reachable(ip, port=22, timeout=3.0):
    print(f"[ssh_scanner_stderr] Checking reachability for {ip}:{port} with timeout {timeout}s", file=sys.stderr)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            print(f"[ssh_scanner_stderr] {ip}:{port} IS reachable.", file=sys.stderr)
            return True
        else:
            print(f"[ssh_scanner_stderr] {ip}:{port} is NOT reachable (connect_ex code: {result}).", file=sys.stderr)
            return False
    except socket.timeout:
        print(f"[ssh_scanner_stderr] Socket timeout checking reachability for {ip}:{port}.", file=sys.stderr)
        return False
    except socket.error as e:
        print(f"[ssh_scanner_stderr] Socket error checking reachability for {ip}:{port} - {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[ssh_scanner_stderr] Generic error checking reachability for {ip}:{port} - {e}", file=sys.stderr)
        return False

def check_weak_ssh_credentials(ip, username, password_to_try):
    print(f"[ssh_scanner_stderr] Attempting SSH to {ip} with {username}:{password_to_try}", file=sys.stderr)
    ssh_client = None
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(ip, username=username, password=password_to_try, 
                           timeout=15, banner_timeout=20, auth_timeout=20,
                           allow_agent=False, look_for_keys=False)
        
        print(f"[ssh_scanner_stderr] SUCCESSFUL weak SSH login to {ip} with {username}:{password_to_try}", file=sys.stderr)
        
        vuln_details_for_pox = {
            "scanner": "ssh_weak_creds_scanner",
            "ip": ip,
            "vulnerability": "weak_ssh_credentials",
            "port": 22,
            "username": username,
            "found_password": password_to_try, # Actual password needed by fixer orchestrator
            "details": f"Weak SSH credentials confirmed for user '{username}' on {ip}.", # Don't put password in detail for POX log
            "severity": "high" 
        }
        print(json.dumps(vuln_details_for_pox)) 
        return True
    except paramiko.AuthenticationException:
        print(f"[ssh_scanner_stderr] Authentication FAILED for {ip} with {username}:{password_to_try}", file=sys.stderr)
    except paramiko.SSHException as e:
        print(f"[ssh_scanner_stderr] SSHException for {ip} with {username}:{password_to_try} - {e}", file=sys.stderr)
    except socket.timeout:
        print(f"[ssh_scanner_stderr] Socket timeout during Paramiko connect to {ip} for user {username}", file=sys.stderr)
    except Exception as e:
        print(f"[ssh_scanner_stderr] Generic Exception during SSH attempt for {ip} with {username}:{password_to_try} - {e}", file=sys.stderr)
    finally:
        if ssh_client:
            ssh_client.close()
    return False

if __name__ == "__main__":
    print("[ssh_scanner_stderr] ssh_scanner.py started.", file=sys.stderr)
    found_any_weakness_this_run = False
    
    for device_ip in TARGET_IPS_FOR_SSH_SCAN:
        if not is_reachable(device_ip, port=22):
            print(f"[ssh_scanner_stderr] Target {device_ip}:22 determined unreachable by pre-check, skipping credential scan for this IP.", file=sys.stderr)
            continue
        
        print(f"[ssh_scanner_stderr] Target {device_ip}:22 is reachable. Proceeding with credential checks.", file=sys.stderr)
        for uname, passwd in WEAK_CREDS:
            if check_weak_ssh_credentials(device_ip, uname, passwd):
                found_any_weakness_this_run = True
                # If you only want to report/fix one weak credential found per host, you could break here.
                # break 
    
    if not found_any_weakness_this_run:
        print(json.dumps({
            "scanner": "ssh_weak_creds_scanner", 
            "status": "scan_complete_no_specific_weak_creds_found_or_targets_unreachable", 
            "targets_checked": TARGET_IPS_FOR_SSH_SCAN
        }))
        print("[ssh_scanner_stderr] No weak SSH credentials (from predefined list) found on targeted IPs, OR targets/ports were unreachable by pre-check.", file=sys.stderr)
    
    print("[ssh_scanner_stderr] ssh_scanner.py scan finished.", file=sys.stderr)
