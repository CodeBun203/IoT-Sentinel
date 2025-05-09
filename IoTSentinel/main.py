from servers.unified_server import UnifiedServer
from servers.dhcp_event_handler import DHCPEventHandler
from utils.logger import setup_logger

def main():
    # Set up centralized logging
    logger = setup_logger("IoTSentinel", "IoTSentinel.log")

    # Example device configurations
    devices = [
        {"name": "Temperature Sensor", "ip": "10.0.0.1"},
        {"name": "Smart Plug", "ip": "10.0.0.2"},
        {"name": "Security Camera", "ip": "10.0.0.3"}
    ]

    # Initialize Unified Server
    logger.info("Initializing Unified Server...")
    server = UnifiedServer(devices)

    # Start Unified Server operations (scanning and fixing vulnerabilities)
    logger.info("Starting server operations...")
    server.start()

    # Simulate DHCP event handling (dynamic device discovery)
    logger.info("Initializing DHCP Event Handler...")
    dhcp_handler = DHCPEventHandler()
    dhcp_handler.device_connected("10.0.0.4", "00:1A:2B:3C:4D:5E")
    dhcp_handler.device_disconnected("10.0.0.1")

    # Wrap up operations
    logger.info("IoTSentinel operations completed.")

if __name__ == "__main__":
    main()
