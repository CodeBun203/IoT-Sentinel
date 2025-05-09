import socket

def close_unnecessary_ports(ip, ports_to_close):
    """
    Sends commands to close unnecessary ports on the IoT device.
    Args:
        ip (str): IP address of the IoT device.
        ports_to_close (list): List of port numbers to close.
    Returns:
        bool: True if ports were successfully closed, False otherwise.
    """
    print(f"Attempting to close ports {ports_to_close} on {ip}...")
    
    for port in ports_to_close:
        try:
            # Simulating the port-closing process (replace with actual device API)
            command = f"close-port {port}"  # Example command to close ports
            print(f"Command sent to {ip}: {command}")
            # Add actual implementation here (e.g., SSH, HTTP API, etc.)
        except Exception as e:
            print(f"Error closing port {port} on {ip}: {e}")
            return False

    print(f"Successfully closed specified ports on {ip}.")
    return True

if __name__ == "__main__":
    # Example usage
    device_ip = "10.0.0.1"
    ports = [21, 23, 2323, 80]  # Common unnecessary ports
    success = close_unnecessary_ports(device_ip, ports)
    if success:
        print("Port closing operation complete.")

