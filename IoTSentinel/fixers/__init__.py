"""
Fixers Package
Contains modules for mitigating vulnerabilities detected in IoT devices.
"""

# Import common fixers for easy access
from .default_credentials_fixer import reset_default_credentials
from .port_closer import close_unnecessary_ports
from .firmware_updater import update_firmware
