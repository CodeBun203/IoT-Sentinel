import paramiko

def reset_default_credentials(ip, old_username, old_password, new_username, new_password):
    """
    Resets default credentials on an IoT device via SSH.
    Args:
        ip (str): IP address of the IoT device.
        old_username (str): Current username.
        old_password (str): Current password.
        new_username (str): New username to set.
        new_password (str): New password to set.
    Returns:
        bool: True if credentials were successfully reset, False otherwise.
    """
    print(f"Attempting to reset credentials for {ip}...")

    try:
        # Connect to the device using SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=old_username, password=old_password, timeout=5)

        # Send command to update credentials
        command = f"set-user {new_username} {new_password}"  # Replace with actual device command
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()

        # Check for errors
        if error:
            print(f"Error resetting credentials on {ip}: {error}")
            return False
        else:
            print(f"Successfully updated credentials on {ip}: {new_username}/{new_password}")
            return True
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {ip}. Check the old credentials.")
    except Exception as e:
        print(f"Error connecting to {ip}: {e}")
    finally:
        ssh.close()
    return False

if __name__ == "__main__":
    # Example usage
    device_ip = "10.0.0.1"
    current_username = "admin"
    current_password = "admin"
    new_username = "secureadmin"
    new_password = "newsecurepassword"

    success = reset_default_credentials(device_ip, current_username, current_password, new_username, new_password)
    if success:
        print("Credential reset complete.")
