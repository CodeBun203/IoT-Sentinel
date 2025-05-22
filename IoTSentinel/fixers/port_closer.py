# /home/mininet/IoTSentinel/fixers/port_closer.py
import paramiko
import json
import sys
import os
import time

DEFAULT_SSH_USER = "user"
DEFAULT_SSH_PASS = "password"

def attempt_iptables_block(ssh_client, target_ip, port_to_close, protocol_lower):
    """Attempts to block a port using iptables via the provided SSH client."""
    check_command = f"sudo iptables -C INPUT -p {protocol_lower} --dport {port_to_close} -j DROP"
    block_command = f"sudo iptables -I INPUT 1 -p {protocol_lower} --dport {port_to_close} -j DROP"

    print(f"[port_closer_stderr] (iptables) Checking if rule exists on {target_ip}: {check_command}", file=sys.stderr)
    stdin_check, stdout_check, stderr_check = ssh_client.exec_command(check_command, timeout=10)
    exit_status_check = stdout_check.channel.recv_exit_status()

    if exit_status_check == 0:
        msg = f"(iptables) Rule to DROP {protocol_lower} dport {port_to_close} already exists on {target_ip}."
        print(f"[port_closer_stderr] {msg}", file=sys.stderr)
        return True, msg

    print(f"[port_closer_stderr] (iptables) Executing block command on {target_ip}: {block_command}", file=sys.stderr)
    stdin_block, stdout_block, stderr_block = ssh_client.exec_command(block_command, timeout=10)
    exit_status_block = stdout_block.channel.recv_exit_status()
    stderr_output_block = stderr_block.read().decode(errors='ignore').strip()

    if exit_status_block == 0:
        msg = f"(iptables) Successfully added rule to DROP {protocol_lower} dport {port_to_close} on {target_ip}."
        print(f"[port_closer_stderr] {msg}", file=sys.stderr)
        return True, msg
    else:
        error_message = f"(iptables) Failed to add rule on {target_ip}. Exit: {exit_status_block}."
        if stderr_output_block:
            error_message += f" Stderr: {stderr_output_block}"
        print(f"[port_closer_stderr] {error_message}", file=sys.stderr)
        return False, error_message

def close_port_on_device(target_ip, port_to_close, protocol, ssh_user=DEFAULT_SSH_USER, ssh_pass=DEFAULT_SSH_PASS, device_os_hint=None):
    print(f"[port_closer_stderr] Attempting to close port {port_to_close}/{protocol} on {target_ip}.", file=sys.stderr)
    protocol_lower = protocol.lower()
    if protocol_lower not in ["tcp", "udp"]:
        return False, f"Invalid protocol '{protocol}'. Must be 'tcp' or 'udp'."

    # Strategy 1: Attempt SSH and iptables (common for Linux-based/Mininet)
    ssh_client = None
    try:
        print(f"[port_closer_stderr] Trying SSH/iptables method for {target_ip}...", file=sys.stderr)
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(target_ip, username=ssh_user, password=ssh_pass,
                           timeout=10, banner_timeout=15, auth_timeout=15,
                           allow_agent=False, look_for_keys=False)
        print(f"[port_closer_stderr] SSH connected to {target_ip} as '{ssh_user}'.", file=sys.stderr)
        
        success, msg = attempt_iptables_block(ssh_client, target_ip, port_to_close, protocol_lower)
        if success:
            return True, msg
        # If iptables failed, msg contains the error. We might try other methods if we knew them.

    except paramiko.AuthenticationException:
        msg = f"SSH auth failed for {target_ip} with user '{ssh_user}'. Cannot attempt iptables."
        print(f"[port_closer_stderr] {msg}", file=sys.stderr)
        # Fall through to other methods if applicable
    except paramiko.SSHException as e:
        msg = f"SSHException for {target_ip} with user '{ssh_user}': {e}. Cannot attempt iptables."
        print(f"[port_closer_stderr] {msg}", file=sys.stderr)
        # Fall through
    except Exception as e: # Other errors like connection timeout for SSH
        msg = f"Generic exception during SSH phase for {target_ip}: {e}. Cannot attempt iptables."
        print(f"[port_closer_stderr] {msg}", file=sys.stderr)
        # Fall through
    finally:
        if ssh_client:
            ssh_client.close()
            print(f"[port_closer_stderr] SSH client for {target_ip} (iptables attempt) closed.", file=sys.stderr)

    # Strategy 2: Placeholder for device-specific API call
    # if device_os_hint == "some_rtos_with_api" or known_api_for_ip(target_ip):
    #     print(f"[port_closer_stderr] Attempting device-specific API for {target_ip}...", file=sys.stderr)
    #     # success, msg = call_device_api_to_close_port(target_ip, port_to_close, protocol)
    #     # if success: return True, msg
    #     pass # Replace with actual API call logic

    # Strategy 3: If all above fail, report inability to fix directly on device.
    # SDN-level blocking via POX ACLManager is a separate, complementary action
    # handled by mqtt_monitor.py based on the vulnerability type.
    final_message = f"No direct on-device method succeeded or available for closing {port_to_close}/{protocol_lower} on {target_ip}. Relies on network-level ACLs if configured by POX."
    print(f"[port_closer_stderr] {final_message}", file=sys.stderr)
    return False, final_message # Indicates on-device closure was not confirmed

if __name__ == "__main__":
    fix_result = {
        "fixer_script": "port_closer.py",
        "target_ip": "N/A",
        "port_protocol": "N/A",
        "action_attempted": "close_or_block_port_on_device",
        "success": False,
        "message": "Fixer not properly invoked or arguments missing."
    }

    if len(sys.argv) >= 4:
        target_ip_arg = sys.argv[1]
        port_arg = sys.argv[2]
        protocol_arg = sys.argv[3]
        
        ssh_user_arg = sys.argv[4] if len(sys.argv) > 4 else DEFAULT_SSH_USER
        ssh_pass_arg = sys.argv[5] if len(sys.argv) > 5 else DEFAULT_SSH_PASS
        # device_os_hint_arg = sys.argv[6] if len(sys.argv) > 6 else None

        fix_result["target_ip"] = target_ip_arg
        fix_result["port_protocol"] = f"{port_arg}/{protocol_arg}"
        
        print(f"[port_closer_main] port_closer.py invoked for {target_ip_arg} to close {port_arg}/{protocol_arg}", file=sys.stderr)
        
        success, message_from_close = close_port_on_device(
            target_ip_arg, port_arg, protocol_arg, 
            ssh_user_arg, ssh_pass_arg #, device_os_hint_arg
        )
        
        fix_result["success"] = success # True if an on-device method confirmed closure
        fix_result["message"] = message_from_close
    else:
        error_msg = "Error: Missing arguments. Usage: python3 port_closer.py <target_ip> <port> <protocol> [ssh_user] [ssh_pass]"
        print(f"[port_closer_main] {error_msg}", file=sys.stderr)
        fix_result["message"] = error_msg

    print(json.dumps(fix_result))
