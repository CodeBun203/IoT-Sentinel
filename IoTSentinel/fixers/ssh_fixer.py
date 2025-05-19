# /home/mininet/IoTSentinel/fixers/ssh_fixer.py
import paramiko
import json
import sys
import os
import random
import string
import time

PROJECT_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CREDENTIAL_LOG_DIR = os.path.join(PROJECT_BASE_DIR, "logs")
NEW_CREDENTIALS_FILE = os.path.join(CREDENTIAL_LOG_DIR, "new_credentials_log.txt")

def generate_strong_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    safe_characters = "".join(c for c in characters if c not in "'\"`$\\!")
    if not safe_characters:
        safe_characters = string.ascii_letters + string.digits 
    password = ''.join(random.choice(safe_characters) for i in range(length))
    return password

def change_password_on_host(target_ip, username, old_password, new_password):
    print(f"[ssh_fixer_stderr] Attempting to change password for '{username}' on {target_ip} from '{old_password}' to '{new_password}'.", file=sys.stderr)
    ssh_client = None
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        print(f"[ssh_fixer_stderr] Connecting to {target_ip} as {username} with old password...", file=sys.stderr)
        ssh_client.connect(target_ip, username=username, password=old_password, 
                           timeout=20, banner_timeout=25, auth_timeout=25,
                           allow_agent=False, look_for_keys=False)
        print(f"[ssh_fixer_stderr] Connected to {target_ip} as {username}.", file=sys.stderr)
        
        command = f"echo '{username}:{new_password}' | sudo chpasswd"
        print(f"[ssh_fixer_stderr] Executing command on {target_ip}: {command.replace(new_password, '********')}", file=sys.stderr)
        
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=15)
        
        exit_status = stdout.channel.recv_exit_status() 
        stderr_output = stderr.read().decode(errors='ignore').strip()
        stdout_output = stdout.read().decode(errors='ignore').strip()

        if exit_status == 0:
            print(f"[ssh_fixer_stderr] Successfully changed password for '{username}' on {target_ip}.", file=sys.stderr)
            return True, f"Password for '{username}' changed successfully to '{new_password}' (actual value logged to secure file)."
        else:
            error_message = f"Failed to change password for '{username}' on {target_ip}. Exit status: {exit_status}."
            if stdout_output: error_message += f" Stdout: {stdout_output}"
            if stderr_output: error_message += f" Stderr: {stderr_output}"
            print(f"[ssh_fixer_stderr] {error_message}", file=sys.stderr)
            return False, error_message

    except paramiko.AuthenticationException:
        msg = f"Authentication failed when trying to connect to {target_ip} with user '{username}' using old password '{old_password}'."
        print(f"[ssh_fixer_stderr] {msg}", file=sys.stderr)
        return False, msg
    except paramiko.SSHException as e:
        msg = f"SSHException occurred for {target_ip} with user '{username}': {e}"
        print(f"[ssh_fixer_stderr] {msg}", file=sys.stderr)
        return False, msg
    except Exception as e:
        msg = f"Generic exception changing password for '{username}' on {target_ip}: {e}"
        print(f"[ssh_fixer_stderr] {msg}", file=sys.stderr)
        return False, msg
    finally:
        if ssh_client:
            ssh_client.close()
        print(f"[ssh_fixer_stderr] SSH client for {target_ip} closed.", file=sys.stderr)

def log_new_credential(target_ip, username, old_password, new_password):
    try:
        os.makedirs(CREDENTIAL_LOG_DIR, exist_ok=True)
        with open(NEW_CREDENTIALS_FILE, "a") as f:
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Host: {target_ip}\n")
            f.write(f"  User: {username}\n")
            f.write(f"  Old Password: {old_password}\n")
            f.write(f"  New Password: {new_password}\n")
            f.write("-" * 30 + "\n")
        print(f"[ssh_fixer_stderr] New credential for {username}@{target_ip} logged to {NEW_CREDENTIALS_FILE}", file=sys.stderr)
    except Exception as e:
        print(f"[ssh_fixer_stderr] ERROR: Could not log new credential: {e}", file=sys.stderr)

if __name__ == "__main__":
    fix_result = {
        "fixer_script": "ssh_fixer.py",
        "target_ip": "N/A",
        "username": "N/A",
        "action_attempted": "change_ssh_password",
        "success": False,
        "message": "Fixer not properly invoked or arguments missing."
        # "new_password_generated_for_log" field removed as it's an internal detail
    }

    if len(sys.argv) == 4:
        target_ip_arg = sys.argv[1]
        username_arg = sys.argv[2]
        old_password_arg = sys.argv[3]

        fix_result["target_ip"] = target_ip_arg
        fix_result["username"] = username_arg
        
        print(f"[ssh_fixer_main] ssh_fixer.py invoked for {username_arg}@{target_ip_arg} with old_password: {old_password_arg}", file=sys.stderr)
        
        new_generated_password = generate_strong_password()
        # Store for logging, but don't put actual new pass in JSON to POX unless strictly necessary and handled securely
        
        success, message_from_change = change_password_on_host(target_ip_arg, username_arg, old_password_arg, new_generated_password)
        
        fix_result["success"] = success
        
        if success:
            log_new_credential(target_ip_arg, username_arg, old_password_arg, new_generated_password)
            fix_result["message"] = f"Password for '{username_arg}' on {target_ip_arg} changed successfully. New password logged."
        else:
            # Sanitize message to ensure new password isn't accidentally leaked if it was in the raw message_from_change
            sanitized_message = str(message_from_change).replace(new_generated_password, "********")
            fix_result["message"] = f"Failed to change password for '{username_arg}'. Reason: {sanitized_message}"
    else:
        print("[ssh_fixer_main] Error: Missing arguments. Usage: python3 ssh_fixer.py <target_ip> <username> <old_password>", file=sys.stderr)
        fix_result["message"] = "Error: ssh_fixer.py called with incorrect arguments."

    # Final JSON output to STDOUT (for POX)
    print(json.dumps(fix_result))
