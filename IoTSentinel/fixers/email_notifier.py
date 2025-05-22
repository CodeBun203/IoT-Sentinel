# /home/mininet/IoTSentinel/fixers/email_notifier.py
import smtplib
import json
import os
import sys
from email.mime.text import MIMEText
import datetime 

# --- Load Email Config ---
PROJECT_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EMAIL_CONFIG_FILE = os.path.join(PROJECT_BASE_DIR, "config", "email_config.json")

email_config = {}

def load_email_config():
    """Loads email configuration from the JSON file."""
    global email_config
    if os.path.exists(EMAIL_CONFIG_FILE):
        try:
            with open(EMAIL_CONFIG_FILE, 'r') as f:
                email_config = json.load(f)
            if "unsubscribed" not in email_config: 
                email_config["unsubscribed"] = False
        except Exception as e:
            print(f"[EmailNotifier ERROR] Could not load email config from {EMAIL_CONFIG_FILE}: {e}", file=sys.stderr)
            email_config = {"unsubscribed": True} 
    else:
        print(f"[EmailNotifier WARNING] Email config file not found at {EMAIL_CONFIG_FILE}. Email notifications disabled.", file=sys.stderr)
        email_config = {"unsubscribed": True} 
    return email_config

def save_email_config():
    """Saves the current email configuration back to the file."""
    global email_config
    try:
        with open(EMAIL_CONFIG_FILE, 'w') as f:
            json.dump(email_config, f, indent=4)
    except Exception as e:
        print(f"[EmailNotifier ERROR] Could not save email config to {EMAIL_CONFIG_FILE}: {e}", file=sys.stderr)

def is_user_subscribed():
    """Checks if the user is currently subscribed to email notifications."""
    return not email_config.get("unsubscribed", False)

def update_user_unsubscribe_status(should_unsubscribe):
    """Updates the user's email subscription status."""
    global email_config
    if not email_config and not os.path.exists(EMAIL_CONFIG_FILE):
        email_config = {
            "smtp_server": "your_server.com", "smtp_port": 587,
            "smtp_user": "user@example.com", "smtp_password": "password",
            "recipient_email": "admin@example.com", "unsubscribed": False
        }
        print(f"[EmailNotifier WARNING] Email config not found, created a default one to store unsubscribe status at {EMAIL_CONFIG_FILE}", file=sys.stderr)

    email_config["unsubscribed"] = should_unsubscribe
    save_email_config()
    status = "unsubscribed" if should_unsubscribe else "subscribed"
    print(f"[EmailNotifier INFO] User email notification status set to: {status}", file=sys.stderr)
    return True

email_config = load_email_config()
SMTP_SERVER = email_config.get("smtp_server")
SMTP_PORT = email_config.get("smtp_port")
SMTP_USER = email_config.get("smtp_user")
SMTP_PASSWORD = email_config.get("smtp_password")
RECIPIENT_EMAIL = email_config.get("recipient_email")

def format_consolidated_vulnerabilities_for_email(vulnerabilities_with_actions):
    if not vulnerabilities_with_actions:
        return "[INFO]", "No new vulnerabilities or significant events detected in this scan cycle."

    body_lines = [
        "Dear IoT Sentinel Administrator,",
        "\nThis is a summary of the latest scan cycle findings and actions:\n",
        "=" * 60
    ]

    for i, (scan_data, action_desc, outcome_msg) in enumerate(vulnerabilities_with_actions):
        body_lines.append(f"\nEntry #{i+1}:")
        
        vuln_type = scan_data.get('vulnerability', 'Unknown Event')
        ip = scan_data.get('ip', 'N/A')
        severity = str(scan_data.get('severity', 'INFO')).upper()
        details = scan_data.get('details', 'No additional details provided by scanner.')
        
        body_lines.append(f"  Event/Vulnerability: {vuln_type} (Severity: {severity})")
        if ip != 'N/A':
            body_lines.append(f"  Target IP: {ip}")

        ports = scan_data.get('ports', scan_data.get('port'))
        if ports:
            body_lines.append(f"  Affected Port(s): {str(ports)}")
        
        if "username" in scan_data and scan_data.get("username"):
            body_lines.append(f"  Affected User: {scan_data['username']}")

        body_lines.append(f"  Scanner Details: {details}")
        body_lines.append(f"  Action Attempted: {action_desc}")
        body_lines.append(f"  Action Outcome: {outcome_msg}")

        # Display new password if ssh_fixer was successful and provided it in the outcome_msg
        password_phrase = "new password set is: "
        if password_phrase in outcome_msg.lower() and \
           (("password for" in outcome_msg.lower() and "changed successfully" in outcome_msg.lower()) or \
            ("new password logged" in outcome_msg.lower())): # Check if it's a password change message
            
            user_changed = scan_data.get("username", "N/A_USER")
            if user_changed == "N/A_USER" and "user '" in outcome_msg:
                try:
                    user_changed = outcome_msg.split("user '")[1].split("'")[0]
                except IndexError:
                    user_changed = "an affected user"
            
            body_lines.append(f"  RECOMMENDATION: The password for '{user_changed}' on {ip} was changed automatically.")
            try:
                password_part = outcome_msg.lower().split(password_phrase, 1)[1].strip()
                actual_new_password = password_part.split(" ")[0] 
                
                if actual_new_password and not actual_new_password.startswith("("): # Basic check to avoid "(actual value logged..."
                     body_lines.append(f"                  The automatically set new password is: {actual_new_password}")
                     body_lines.append(f"                  SECURITY WARNING: This password is included for your convenience during testing.")
                     body_lines.append(f"                                  Transmitting passwords via email is insecure and NOT recommended for production.")
                else: 
                    body_lines.append(f"                  The new password was logged securely. Please check IoTSentinel/logs/new_credentials_log.txt")
            except Exception as e: 
                print(f"[EmailNotifier WARN] Could not parse new password from outcome: {outcome_msg}. Error: {e}", file=sys.stderr)
                body_lines.append(f"                  The new password was logged securely. Please check IoTSentinel/logs/new_credentials_log.txt")
            body_lines.append(f"                  It is strongly advised to log in with this new password and change it to a strong, memorable one of your choice.")
        
        body_lines.append("-" * 60)
    
    body_lines.append("\nPlease review the system logs for more detailed information.")
    body_lines.append("\nRegards,\nIoT Sentinel System")
    
    email_body = "\n".join(body_lines)
    
    highest_severity_val = 0 
    severity_map = {"INFO":0, "LOW":1, "MEDIUM":2, "HIGH":3, "CRITICAL":4, "ERROR":4}
    for item, _, _ in vulnerabilities_with_actions:
        sev = str(item.get("severity", "INFO")).upper()
        highest_severity_val = max(highest_severity_val, severity_map.get(sev, 0))
    
    subject_severity_prefix = "[INFO]"
    if highest_severity_val == 1: subject_severity_prefix = "[LOW Alert]"
    elif highest_severity_val == 2: subject_severity_prefix = "[MEDIUM Alert]"
    elif highest_severity_val == 3: subject_severity_prefix = "[HIGH Alert]"
    elif highest_severity_val >= 4: subject_severity_prefix = "[CRITICAL Alert]"
        
    return subject_severity_prefix, email_body

def send_consolidated_email_notification(subject_prefix, formatted_vulnerabilities_body):
    if not is_user_subscribed():
        print("[EmailNotifier SKIPPED] User is unsubscribed. No email sent.", file=sys.stderr)
        return True 

    current_smtp_user = email_config.get("smtp_user")
    current_recipient = email_config.get("recipient_email")

    if not all([SMTP_SERVER, SMTP_PORT, current_smtp_user, SMTP_PASSWORD, current_recipient]):
        print("[EmailNotifier SKIPPED] Email configuration is incomplete for consolidated email.", file=sys.stderr)
        print(f"    Subject Prefix: {subject_prefix}\n    Body Preview (first 200 chars): {formatted_vulnerabilities_body[:200]}...", file=sys.stderr)
        return False

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_subject = f"IoT Sentinel {subject_prefix}: Scan Report {timestamp}"

    unsubscribe_instruction = (
        f"\n\n---\nTo manage email notification preferences, please refer to the IoT Sentinel application "
        f"or contact your administrator. (Email: {current_recipient})"
    )
    final_body = formatted_vulnerabilities_body + unsubscribe_instruction

    msg = MIMEText(final_body, 'plain')
    msg['Subject'] = full_subject
    msg['From'] = current_smtp_user
    msg['To'] = current_recipient

    try:
        print(f"[EmailNotifier INFO] Attempting to send consolidated email to {current_recipient} via {SMTP_SERVER}:{SMTP_PORT}", file=sys.stderr)
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(current_smtp_user, SMTP_PASSWORD)
            server.sendmail(current_smtp_user, current_recipient, msg.as_string())
        print(f"[EmailNotifier SUCCESS] Consolidated email sent successfully to {current_recipient}", file=sys.stderr)
        return True
    except Exception as e:
        print(f"[EmailNotifier FAILED] Could not send consolidated email: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    print("[EmailNotifier Direct Test - Consolidated] Running direct test...", file=sys.stderr)
    
    if not is_user_subscribed():
        print(f"User ({RECIPIENT_EMAIL}) is unsubscribed. Direct test email will not be sent.", file=sys.stderr)
    elif not all([SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, RECIPIENT_EMAIL]):
        print("Please set up your email credentials in IoTSentinel/config/email_config.json", file=sys.stderr)
    else:
        test_vulns_and_actions = [
            (
                {"ip": "10.0.0.3", "vulnerability": "weak_ssh_credentials", "username": "user", "severity": "HIGH", "details": "User 'user' had a weak password."},
                "Ran fixer 'ssh_fixer' for IP '10.0.0.3' user 'user'", 
                "Password for 'user' on 10.0.0.3 changed successfully. New password logged and included in this result. The new password set is: TestPass123!" 
            ),
            (
                {"ip": "10.0.0.2", "vulnerability": "open_telnet_port", "ports": [23], "severity": "CRITICAL", "details": "Telnet open on device."},
                "Ran fixer 'port_closer' for IP '10.0.0.2'", 
                "No direct on-device method succeeded for closing 23/tcp on 10.0.0.2. POX additionally applied a network ACL to block incoming traffic to port 23/tcp on 10.0.0.2."
            )
        ]
        if test_vulns_and_actions:
            subject_prefix, email_body = format_consolidated_vulnerabilities_for_email(test_vulns_and_actions)
            print("\n--- Sample Email Body ---")
            print(email_body)
            print("--- End Sample Email Body ---\n")
            send_consolidated_email_notification(subject_prefix, email_body)
