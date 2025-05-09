import threading
from scanners.iot_scanner import scan_iot_device
from scanners.ssh_scanner import check_weak_ssh_credentials
from fixers.default_credentials_fixer import reset_default_credentials
from fixers.port_closer import close_unnecessary_ports
from fixers.firmware_updater import update_firmware

class UnifiedServer:
    """
    Centralized server to manage scanning and fixing IoT devices.
    """
    def __init__(self, devices):
        self.devices = devices

    def run_scans(self):
        """
        Runs all scanners on each device in the list.
        """
        print("Starting vulnerability scans...")
        for device in self.devices:
            print(f"Scanning device: {device['name']} ({device['ip']})")
            open_ports = scan_iot_device(device['ip'], [21, 22, 80, 443])
            for username, password in [("admin", "admin"), ("root", "1234")]:
                check_weak_ssh_credentials(device['ip'], username, password)
            print(f"Completed scans for: {device['name']}")

    def apply_fixes(self):
        """
        Applies fixes for detected vulnerabilities.
        """
        print("Applying fixes...")
        for device in self.devices:
            print(f"Applying fixes to device: {device['name']} ({device['ip']})")
            reset_default_credentials(device['ip'], "admin", "admin", "secureadmin", "newsecurepassword")
            close_unnecessary_ports(device['ip'], [21, 23, 2323])
            update_firmware(device['ip'], "http://firmware-server.com/firmware.bin")
            print(f"Completed fixes for: {device['name']}")

    def start(self):
        """
        Starts the server to scan and fix IoT devices in separate threads.
        """
        print("Starting Unified Server...")
        scan_thread = threading.Thread(target=self.run_scans)
        fix_thread = threading.Thread(target=self.apply_fixes)

        scan_thread.start()
        fix_thread.start()

        scan_thread.join()
        fix_thread.join()
        print("Unified Server operations complete.")

if __name__ == "__main__":
    devices = [
        {"name": "Temperature Sensor", "ip": "10.0.0.1"},
        {"name": "Smart Plug", "ip": "10.0.0.2"},
        {"name": "Security Camera", "ip": "10.0.0.3"}
    ]
    server = UnifiedServer(devices)
    server.start()
