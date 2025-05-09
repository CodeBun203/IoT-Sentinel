import requests

def update_firmware(ip, firmware_url):
    """
    Updates the firmware on an IoT device.
    Args:
        ip (str): IP address of the IoT device.
        firmware_url (str): URL to the firmware binary.
    Returns:
        bool: True if the update was successful, False otherwise.
    """
    print(f"Starting firmware update for {ip} from {firmware_url}...")

    try:
        # Simulating HTTP POST request to upload firmware (replace with actual device API)
        endpoint = f"http://{ip}/update-firmware"
        payload = {"firmware": firmware_url}
        response = requests.post(endpoint, data=payload, timeout=10)

        if response.status_code == 200:
            print(f"Firmware update successful for {ip}.")
            return True
        else:
            print(f"Failed to update firmware for {ip}. HTTP status: {response.status_code}")
            return False
    except Exception as e:
        print(f"Error during firmware update for {ip}: {e}")
        return False

if __name__ == "__main__":
    # Example usage

    device_ip = "10.0.0.1"
    firmware_binary_url = "http://firmware-server.com/firmware.bin"
    success = update_firmware(device_ip, firmware_binary_url)
    if success:
        print("Firmware update operation complete.")
