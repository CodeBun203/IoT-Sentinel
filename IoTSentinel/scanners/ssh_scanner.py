import os
import paramiko

def get_all_ips():
    """Retrieve all active network devices dynamically."""
    result = os.popen("ifconfig | grep 'inet ' | awk '{print $2}'").read().split("\n")
    return [ip.strip() for ip in result if ip and not ip.startswith("127.")]

def check_weak_ssh_credentials(ip, username, password):
    """Attempts SSH login using weak credentials."""
    print(f"[SCANNER] Checking SSH credentials for {ip}: {username}/{password}")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=5)
        print(f"[VULNERABILITY] Weak SSH credentials detected on {ip}: {username}/{password}")
        ssh.close()
        return True
    except paramiko.AuthenticationException:
        print(f"[SECURE] Credentials denied for {ip}: {username}/{password}")
    except Exception as e:
        print(f"[ERROR] Could not connect to {ip}: {e}")
    return False

# Scan all detected devices
all_devices = get_all_ips()
test_credentials = [("admin", "admin"), ("root", "1234"), ("user", "password")]

for device_ip in all_devices:
    for username, password in test_credentials:
        check_weak_ssh_credentials(device_ip, username, password)
