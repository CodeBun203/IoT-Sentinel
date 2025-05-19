# /home/mininet/IoTSentinel/fixers/email_notifier.py
import smtplib
import json
import os
import sys
from email.mime.text import MIMEText
import datetime # For timestamping the consolidated email

# --- Load Email Config ---
PROJECT_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EMAIL_CONFIG_FILE = os.path.join(PROJECT_BASE_DIR, "config", "email_config.json")

email_config = {}
if os.path.exists(EMAIL_CONFIG_FILE):
    try:
        with open(EMAIL_CONFIG_FILE, 'r') as f:
            email_config = json.load(f)
        print(f"[EmailNotifier INFO] Successfully loaded email config from {EMAIL_CONFIG_FILE}", file=sys.stderr)
    except Exception as e:
        print(f"[EmailNotifier ERROR] Could not load email config from {EMAIL_CONFIG_FILE}: {e}", file=sys.stderr)
else:
    print(f"[EmailNotifier WARNING] Email config file not found at {EMAIL_CONFIG_FILE}", file=sys.stderr)

SMTP_SERVER = email_config.get("smtp_server")
SMTP_PORT = email_config.get("smtp_port")
SMTP_USER = email_config.get("smtp_user")
SMTP_PASSWORD = email_config.get("smtp_password")
RECIPIENT_EMAIL = email_config.get("recipient_email")

def send_consolidated_email_notification(subject_prefix, formatted_vulnerabilities_body):
    """
    Sends a single consolidated email notification.
    """
    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, RECIPIENT_EMAIL]):
        print("[EmailNotifier SKIPPED] Email configuration is incomplete for consolidated email.", file=sys.stderr)
        print(f"    Subject Prefix: {subject_prefix}\n    Body: {formatted_vulnerabilities_body}", file=sys.stderr)
        return False

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_subject = f"IoT Sentinel {subject_prefix}: Scan Report {timestamp}"

    msg = MIMEText(formatted_vulnerabilities_body, 'plain') # Ensure using plain text or html as needed
    msg['Subject'] = full_subject
    msg['From'] = SMTP_USER
    msg['To'] = RECIPIENT_EMAIL

    try:
        print(f"[EmailNotifier INFO] Attempting to send consolidated email to {RECIPIENT_EMAIL} via {SMTP_SERVER}:{SMTP_PORT}", file=sys.stderr)
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, RECIPIENT_EMAIL, msg.as_string())
        print(f"[EmailNotifier SUCCESS] Consolidated email sent successfully to {RECIPIENT_EMAIL}", file=sys.stderr)
        return True
    except Exception as e:
        print(f"[EmailNotifier FAILED] Could not send consolidated email: {e}", file=sys.stderr)
        return False

def format_consolidated_vulnerabilities_for_email(vulnerabilities_with_actions):
    """
    Formats a list of vulnerabilities and fixer outcomes into a single email body.
    vulnerabilities_with_actions is a list of tuples: 
        [(scan_result_data, action_taken, action_outcome), ...]
    """
    if not vulnerabilities_with_actions:
        return "No new vulnerabilities or significant events detected in this scan cycle."

    body = f"Dear IoT Sentinel Administrator,\n\nThis is a summary of the latest scan cycle findings and actions:\n\n"
    body += "=" * 40 + "\n"

    for i, (scan_data, action, outcome) in enumerate(vulnerabilities_with_actions):
        ip = scan_data.get('ip', 'N/A')
        vuln_type = scan_data.get('vulnerability', 'Unknown Vulnerability')
        ports = scan_data.get('ports', scan_data.get('port', 'N/A'))
        severity = str(scan_data.get('severity', 'N/A')).upper()
        details = scan_data.get('details', 'No additional details.')

        body += f"Entry #{i+1}:\n"
        body += f"  Severity: {severity}\n"
        body += f"  Device IP: {ip}\n"
        body += f"  Vulnerability Type: {vuln_type}\n"
        if ports != 'N/A':
            body += f"  Port(s) Affected: {str(ports)}\n"
        body += f"  Details: {details}\n"
        body += f"  Fixer Action Attempted: {action}\n"
        body += f"  Fixer Action Outcome: {outcome}\n"
        body += "-" * 40 + "\n\n"
    
    body += "Please review the system logs for more detailed information.\n\n"
    body += "Regards,\nIoT Sentinel System"
    
    # Determine a summary subject prefix (e.g., based on highest severity)
    highest_severity = "INFO"
    severities_found = [item[0].get("severity", "INFO").upper() for item in vulnerabilities_with_actions]
    if "CRITICAL" in severities_found: highest_severity = "CRITICAL"
    elif "HIGH" in severities_found: highest_severity = "HIGH"
    elif "MEDIUM" in severities_found: highest_severity = "MEDIUM"
    elif "LOW" in severities_found: highest_severity = "LOW"
        
    subject_prefix = f"[{highest_severity} Aler(s)]" if severities_found else "[INFO]"
    return subject_prefix, body


# Example usage for direct testing (optional)
if __name__ == "__main__":
    print("[EmailNotifier Direct Test - Consolidated] Running direct test...", file=sys.stderr)
    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, RECIPIENT_EMAIL]):
        print("Please set up your email credentials in IoTSentinel/config/email_config.json", file=sys.stderr)
    else:
        test_vulns = [
            (
                {"ip": "10.0.0.2", "vulnerability": "open_telnet_port", "ports": [23], "severity": "CRITICAL", "details": "Telnet open"},
                "Attempted to disable Telnet.", "Failed: Manual intervention needed."
            ),
            (
                {"ip": "10.0.0.3", "vulnerability": "weak_ssh_credentials", "username": "user", "found_password": "password", "severity": "HIGH", "details": "User 'user' has weak password."},
                "ssh_fixer for user 'user'", "Success: Password changed and logged."
            ),
            (
                {"ip": "10.0.0.4", "vulnerability": "open_ports", "ports": [80], "severity": "MEDIUM", "details": "HTTP port open"},
                "None (No fixer for generic HTTP)", "Manual investigation advised."
            )
        ]
        if test_vulns:
            subject_prefix, email_body = format_consolidated_vulnerabilities_for_email(test_vulns)
            send_consolidated_email_notification(subject_prefix, email_body)
        else:
            # Test no vulnerabilities found
            subject_prefix, email_body = format_consolidated_vulnerabilities_for_email([])
            send_consolidated_email_notification(subject_prefix, email_body)
