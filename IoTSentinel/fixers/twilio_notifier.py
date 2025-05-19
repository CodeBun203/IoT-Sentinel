# /home/mininet/IoTSentinel/fixers/twilio_notifier.py
import os
import json
import sys # Import sys for stderr
from twilio.rest import Client

# --- Load Twilio Config ---
# Determine the base directory of the IoTSentinel project
# Assumes twilio_notifier.py is in IoTSentinel/fixers/
# So, os.path.dirname(__file__) is IoTSentinel/fixers/
# And os.path.join(os.path.dirname(__file__), "..") is IoTSentinel/
PROJECT_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TWILIO_CONFIG_FILE = os.path.join(PROJECT_BASE_DIR, "config", "twilio_config.json")

# Expected twilio_config.json structure in IoTSentinel/config/twilio_config.json:
# {
#     "account_sid": "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
#     "auth_token": "your_auth_token",
#     "twilio_phone_number": "+12345678901",
#     "recipient_phone_number": "+19876543210"
# }

twilio_config = {}
if os.path.exists(TWILIO_CONFIG_FILE):
    try:
        with open(TWILIO_CONFIG_FILE, 'r') as f:
            twilio_config = json.load(f)
        print(f"[TwilioNotifier INFO] Successfully loaded Twilio config from {TWILIO_CONFIG_FILE}", file=sys.stderr)
    except Exception as e:
        print(f"[TwilioNotifier ERROR] Could not load Twilio config from {TWILIO_CONFIG_FILE}: {e}", file=sys.stderr)
else:
    print(f"[TwilioNotifier WARNING] Twilio config file not found at {TWILIO_CONFIG_FILE}", file=sys.stderr)

ACCOUNT_SID = twilio_config.get("account_sid") or os.environ.get("TWILIO_ACCOUNT_SID")
AUTH_TOKEN = twilio_config.get("auth_token") or os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = twilio_config.get("twilio_phone_number") or os.environ.get("TWILIO_PHONE_NUMBER")
RECIPIENT_PHONE_NUMBER = twilio_config.get("recipient_phone_number") or os.environ.get("RECIPIENT_PHONE_NUMBER")

twilio_client = None
if ACCOUNT_SID and AUTH_TOKEN and TWILIO_PHONE_NUMBER:
    try:
        twilio_client = Client(ACCOUNT_SID, AUTH_TOKEN)
        print("[TwilioNotifier INFO] Twilio client initialized.", file=sys.stderr)
    except Exception as e:
        print(f"[TwilioNotifier ERROR] Failed to initialize Twilio client: {e}", file=sys.stderr)
else:
    required_vars = ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_PHONE_NUMBER", "RECIPIENT_PHONE_NUMBER"]
    missing_vars = [var for var in required_vars if not (twilio_config.get(var.lower()) or os.environ.get(var))]
    print(f"[TwilioNotifier WARNING] Twilio credentials not fully configured. Missing: {missing_vars}. Notifications will be disabled.", file=sys.stderr)


def send_notification(subject, body_message):
    """
    Sends an SMS notification using Twilio.
    """
    if not twilio_client or not RECIPIENT_PHONE_NUMBER or not TWILIO_PHONE_NUMBER:
        print("[TwilioNotifier SKIPPED] Twilio client, recipient, or sender number not configured.", file=sys.stderr)
        print(f"    Subject: {subject}", file=sys.stderr)
        print(f"    Body: {body_message}", file=sys.stderr)
        return False

    full_message_body = f"IoT Sentinel Alert: {subject}\n\n{body_message}"

    try:
        message = twilio_client.messages.create(
            body=full_message_body,
            from_=TWILIO_PHONE_NUMBER,
            to=RECIPIENT_PHONE_NUMBER
        )
        print(f"[TwilioNotifier SUCCESS] Notification sent to {RECIPIENT_PHONE_NUMBER}. SID: {message.sid}", file=sys.stderr)
        return True
    except Exception as e:
        print(f"[TwilioNotifier FAILED] Could not send notification: {e}", file=sys.stderr)
        return False

def format_vulnerability_message(scan_result_data, action_taken="None", action_outcome="N/A"):
    """
    Formats a message string based on the scan result and actions taken.
    scan_result_data is expected to be a dictionary like those from the scanners.
    """
    ip = scan_result_data.get('ip', 'N/A')
    vuln_type = scan_result_data.get('vulnerability', 'Unknown Vulnerability')
    ports = scan_result_data.get('ports', scan_result_data.get('port', 'N/A'))
    severity = str(scan_result_data.get('severity', 'N/A')).upper() # Ensure severity is string
    details = scan_result_data.get('details', 'No additional details.')
    
    subject = f"[{severity}] {vuln_type} on {ip}"
    
    body = f"Vulnerability Detected:\n"
    body += f"  Device IP: {ip}\n"
    body += f"  Type: {vuln_type}\n"
    if ports != 'N/A':
        body += f"  Port(s): {str(ports)}\n" # Ensure ports is string
    body += f"  Severity: {severity}\n"
    body += f"  Details: {details}\n\n"
    
    body += f"Fixer Action Attempted: {action_taken}\n"
    body += f"Fixer Action Outcome: {action_outcome}\n"
    
    return subject, body

if __name__ == "__main__":
    print("[TwilioNotifier Direct Test] Running direct test...", file=sys.stderr)
    if not (ACCOUNT_SID and AUTH_TOKEN and TWILIO_PHONE_NUMBER and RECIPIENT_PHONE_NUMBER):
        print("Please set up your Twilio credentials in IoTSentinel/config/twilio_config.json or as environment variables:", file=sys.stderr)
        print("TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER, RECIPIENT_PHONE_NUMBER", file=sys.stderr)
    else:
        example_scan_result = {
            "scanner": "ssh_weak_creds_scanner",
            "ip": "10.0.0.3",
            "vulnerability": "weak_ssh_credentials",
            "port": 22,
            "username": "user",
            "found_password": "password", # Added for context
            "details": "Weak SSH credentials found for user 'user' on 10.0.0.3.",
            "severity": "high"
        }
        
        subject, body = format_vulnerability_message(
            example_scan_result,
            action_taken="Attempted to change SSH password for user 'user'. Old: 'password', New: 'GeneratedStrongPass123!'",
            action_outcome="Success (Simulated)"
        )
        send_notification(subject, body)

        example_scan_result_telnet = {
            "scanner": "iot_port_scanner",
            "ip": "10.0.0.2",
            "vulnerability": "open_telnet_port", # Example type
            "ports": [23],
            "details": "Device 10.0.0.2 has open Telnet port 23.",
            "severity": "critical"
        }
        subject, body = format_vulnerability_message(
            example_scan_result_telnet,
            action_taken="Attempted to disable Telnet service (inetd).",
            action_outcome="Failed - Simulated permission denied."
        )
        send_notification(subject, body)
