import logging

class DHCPEventHandler:
    """
    Handles DHCP events to monitor network changes and detect new devices.
    """
    def __init__(self):
        self.devices = []
        self.logger = logging.getLogger("DHCPEventHandler")
        logging.basicConfig(level=logging.INFO)

    def device_connected(self, ip, mac):
        """
        Handles a new device connection event.
        Args:
            ip (str): IP address of the new device.
            mac (str): MAC address of the new device.
        """
        self.logger.info(f"New device detected: IP={ip}, MAC={mac}")
        self.devices.append({"ip": ip, "mac": mac})
        self.logger.info(f"Device list updated: {self.devices}")

    def device_disconnected(self, ip):
        """
        Handles a device disconnection event.
        Args:
            ip (str): IP address of the device to remove.
        """
        self.logger.info(f"Device disconnected: IP={ip}")
        self.devices = [device for device in self.devices if device["ip"] != ip]
        self.logger.info(f"Device list updated: {self.devices}")

if __name__ == "__main__":
    # Example usage
    dhcp_handler = DHCPEventHandler()

    # Simulate a device connection
    dhcp_handler.device_connected("10.0.0.10", "00:1A:2B:3C:4D:5E")

    # Simulate a device disconnection
    dhcp_handler.device_disconnected("10.0.0.10")
