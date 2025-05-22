# /home/mininet/IoTSentinel/fixers/default_credentials_fixer.py
import paramiko
import json
import sys
import os
import random
import string
import time

# Define where to log newly set credentials (similar to ssh_fixer.py)
PROJECT_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CREDENTIAL_LOG_DIR = os.path.join(PROJECT_BASE_DIR, "logs")
DEFAULT_CREDENTIALS_LOG_FILE = os.path.join(CREDENTIAL_LOG_DIR, "changed_default_credentials_log.txt")

DEFAULT_NEW_USERNAME_PREFIX = "iotsecureuser"

def generate_strong_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    # Remove characters that might cause issues in shell commands if not handled perfectly
    safe_characters = "".join(c for c in characters if c not in "'\"`$\\!") 
    if not safe_characters: # Fallback if all are problematic (unlikely)
        safe_characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(safe_characters) for i in range(length))
    return password

def log_changed_credential(target_ip, old_username, new_username, new_password):
    try:
        os.makedirs(CREDENTIAL_LOG_DIR, exist_ok=True)
        with open(DEFAULT_CREDENTIALS_LOG_FILE, "a") as f:
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Host: {target_ip}\n")
            f.write(f"  Old Username: {old_username}\n")
            f.write(f"  New Username: {new_username}\n")
            f.write(f"  New Password: {new_password} (Ensure this log is secured)\n")
            f.write("-" * 30 + "\n")
        print(f"[default_creds_fixer_stderr] Changed credential for {old_username}@{target_ip} to {new_username} logged to {DEFAULT_CREDENTIALS_LOG_FILE}", file=sys.stderr)
    except Exception as e:
        print(f"[default_creds_fixer_stderr] ERROR: Could not log changed default credential: {e}", file=sys.stderr)

def reset_default_credentials_via_ssh(ip, old_username, old_password, attempt_user_change=False):
    """
    Attempts to reset default credentials on a device via SSH.
    It will primarily try to change the password for old_username.
    If attempt_user_change is True, it might try to create a new user (more complex and less reliable).
    For now, it focuses on changing the password for the existing default user.
    """
    print(f"[default_creds_fixer_stderr] Attempting to reset default credentials for user '{old_username}' on {ip} (was '{old_password}').", file=sys.stderr)
    ssh_client = None
    new_password = generate_strong_password()
    # For simplicity, we'll keep the username the same unless future logic is added to change it.
    # If we were to change username, it's more involved (e.g. usermod, adduser, checking sudo access etc.)
    new_username = old_username 

    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        print(f"[default_creds_fixer_stderr] Connecting to {ip} as '{old_username}' with default password...", file=sys.stderr)
        ssh_client.connect(ip, username=old_username, password=old_password, 
                           timeout=20, banner_timeout=25, auth_timeout=25,
                           allow_agent=False, look_for_keys=False)
        print(f"[default_creds_fixer_stderr] Connected to {ip} as '{old_username}'.", file=sys.stderr)
        
        # Command to change password for the current user (old_username)
        # This assumes 'chpasswd' utility is available and user has sudo rights or can change own password.
        # The 'echo ... | sudo chpasswd' is a common way.
        # Simpler if user can change their own pass: `passwd` (but it's interactive)
        # Using chpasswd is more script-friendly.
        command = f"echo '{old_username}:{new_password}' | sudo chpasswd"
        print(f"[default_creds_fixer_stderr] Executing command on {ip}: {command.replace(new_password, '********')}", file=sys.stderr)
        
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=15)
        exit_status = stdout.channel.recv_exit_status() 
        
        stderr_output = stderr.read().decode(errors='ignore').strip()
        stdout_output = stdout.read().decode(errors='ignore').strip()

        if exit_status == 0:
            msg = f"Successfully changed password for default user '{old_username}' on {ip}."
            print(f"[default_creds_fixer_stderr] {msg}", file=sys.stderr)
            log_changed_credential(ip, old_username, new_username, new_password)
            return True, msg, new_username, new_password # Return new details
        else:
            error_message = f"Failed to change password for '{old_username}' on {ip}. Exit status: {exit_status}."
            if stdout_output: error_message += f" Stdout: {stdout_output}"
            if stderr_output: error_message += f" Stderr: {stderr_output}"
            print(f"[default_creds_fixer_stderr] {error_message}", file=sys.stderr)
            return False, error_message, old_username, old_password # Return old details on failure

    except paramiko.AuthenticationException:
        msg = f"Authentication failed for {ip} with default user '{old_username}' and password '{old_password}'. Fixer cannot proceed."
        print(f"[default_creds_fixer_stderr] {msg}", file=sys.stderr)
        return False, msg, old_username, old_password
    except paramiko.SSHException as e:
        msg = f"SSHException occurred for {ip} with user '{old_username}': {e}"
        print(f"[default_creds_fixer_stderr] {msg}", file=sys.stderr)
        return False, msg, old_username, old_password
    except Exception as e:
        msg = f"Generic exception changing password for '{old_username}' on {ip}: {e}"
        print(f"[default_creds_fixer_stderr] {msg}", file=sys.stderr)
        return False, msg, old_username, old_password
    finally:
        if ssh_client:
            ssh_client.close()
        print(f"[default_creds_fixer_stderr] SSH client for {ip} (default creds fixer) closed.", file=sys.stderr)


if __name__ == "__main__":
    fix_result = {
        "fixer_script": "default_credentials_fixer.py",
        "target_ip": "N/A",
        "old_username": "N/A",
        "action_attempted": "reset_default_ssh_credentials",
        "success": False,
        "message": "Fixer not properly invoked or arguments missing.",
        "new_username_set": "N/A" 
        # "new_password_set" is not included in JSON output for security, but logged to file.
    }

    if len(sys.argv) == 4: # ip, old_username, old_password
        target_ip_arg = sys.argv[1]
        old_username_arg = sys.argv[2]
        old_password_arg = sys.argv[3]

        fix_result["target_ip"] = target_ip_arg
        fix_result["old_username"] = old_username_arg
        
        print(f"[default_creds_fixer_main] default_credentials_fixer.py invoked for {old_username_arg}@{target_ip_arg}", file=sys.stderr)
        
        # Attempt to change the password for the existing default user
        success, message_from_change, final_username, _ = \
            reset_default_credentials_via_ssh(target_ip_arg, old_username_arg, old_password_arg)
        
        fix_result["success"] = success
        fix_result["message"] = message_from_change
        fix_result["new_username_set"] = final_username # Will be same as old if only password changed

        if success:
            fix_result["message"] = f"Default credentials for user '{old_username_arg}' on {target_ip_arg} addressed. New password logged securely."
        # else: message_from_change already contains the error

    else:
        error_msg = "Error: Missing arguments. Usage: python3 default_credentials_fixer.py <target_ip> <old_username> <old_password>"
        print(f"[default_creds_fixer_main] {error_msg}", file=sys.stderr)
        fix_result["message"] = error_msg

    print(json.dumps(fix_result))
