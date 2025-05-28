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
            # Fallback print if log object isn't available here
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
    # Ensure config is loaded if it hasn't been already
    if not email_config:
        load_email_config()
    return not email_config.get("unsubscribed", False)

def update_user_unsubscribe_status(should_unsubscribe):
    """Updates the user's email subscription status."""
    global email_config
    if not email_config and not os.path.exists(EMAIL_CONFIG_FILE): # If config is empty and file doesn't exist
        # Create a default config structure to save the unsubscribe status
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

# Load config when module is imported
email_config = load_email_config()
# These globals are set after load_email_config()
SMTP_SERVER = email_config.get("smtp_server")
SMTP_PORT = email_config.get("smtp_port")
SMTP_USER = email_config.get("smtp_user")
SMTP_PASSWORD = email_config.get("smtp_password")
RECIPIENT_EMAIL = email_config.get("recipient_email")

def format_consolidated_vulnerabilities_for_email(vulnerabilities_with_actions):
    # vulnerabilities_with_actions is a list of tuples:
    # (scan_data_dict, action_description_str, outcome_message_str)

    if not vulnerabilities_with_actions:
        return "[INFO]", "No new vulnerabilities or significant actionable events detected in this scan cycle."

    body_lines = [
        "Dear IoT Sentinel Administrator,",
        "\nThis is a summary of the latest scan cycle findings and actions:\n",
        "=" * 60
    ]
    
    highest_severity_val = 0 
    # Define a mapping for severity to numeric value for sorting/prioritizing if needed
    severity_map = {"INFO":0, "LOW":1, "MEDIUM":2, "HIGH":3, "CRITICAL":4, "ERROR":4}
    entry_count = 0

    for i, event_tuple in enumerate(vulnerabilities_with_actions):
        scan_data, action_desc, outcome_msg = event_tuple
        
        # Skip reporting for entries that are purely status updates from scanners
        # if not scan_data.get("vulnerability"): 
        #     continue # This was handled by filter in mqtt_monitor before calling this

        entry_count += 1
        body_lines.append(f"\nEntry #{entry_count}:")
        
        ip_affected = scan_data.get('ip', 'N/A')
        vuln_type = scan_data.get('vulnerability', 'Unknown Event')
        severity = str(scan_data.get('severity', 'INFO')).upper()
        
        current_sev_val = severity_map.get(severity, 0)
        if current_sev_val > highest_severity_val:
            highest_severity_val = current_sev_val

        body_lines.append(f"  Device IP: {ip_affected}")
        body_lines.append(f"  Issue: {vuln_type} (Severity: {severity})")

        details_parts = []
        if "ports" in scan_data and scan_data["ports"]:
            details_parts.append(f"Port(s): {scan_data['ports']}")
        if "username" in scan_data and scan_data["username"]:
            details_parts.append(f"User: {scan_data['username']}")
        if not details_parts and "details" in scan_data: # Fallback to original details if no specific parts
            details_parts.append(f"Details: {scan_data['details'][:100]}{'...' if len(scan_data['details']) > 100 else ''}")
        
        if details_parts:
            body_lines.append(f"  Context: {'; '.join(details_parts)}")

        fix_attempted_msg = "No (Not applicable or no fixer configured)"
        if "Ran fixer" in action_desc or "Fixer dispatched" in outcome_msg or "Threshold breached" in outcome_msg: # Check for more keywords
            fix_attempted_msg = f"Yes ({action_desc.replace('Ran fixer ', '').split(' for IP')[0]})" # Extract fixer name
        elif "No specific auto-fixer configured" in outcome_msg or "No fixer configured" in outcome_msg:
             fix_attempted_msg = "No (Fixer not configured for this issue)"


        body_lines.append(f"  Fix Attempted: {fix_attempted_msg}")
        
        # Summarize outcome message
        summarized_outcome = outcome_msg
        if "New password set is:" in outcome_msg:
            summarized_outcome = "Password changed successfully. New password logged."
        elif "POX additionally applied a network ACL" in outcome_msg:
            summarized_outcome = "On-device fix failed/skipped. Network ACL applied by POX."
        elif "ddos_fixer suggested blocking. POX applied network ACLs:" in outcome_msg:
            summarized_outcome = "DDoS Fixer suggested blocks; POX applied network ACLs."
        elif "No direct on-device method succeeded" in outcome_msg and "Relies on network-level ACLs" in outcome_msg:
            summarized_outcome = "On-device fix failed. Relies on POX ACLs if configured."


        body_lines.append(f"  Fix Result/Outcome: {summarized_outcome[:250]}{'...' if len(summarized_outcome) > 250 else ''}")
        body_lines.append("-" * 60)
    
    if entry_count == 0: # All items were filtered out (e.g., only status messages)
        return "[INFO]", "No new actionable vulnerabilities detected in this scan cycle."

    body_lines.append("\nPlease review the system UI logs for more detailed information.")
    body_lines.append("\nRegards,\nIoT Sentinel System")
    
    email_body = "\n".join(body_lines)
    
    subject_severity_prefix = "[INFO]"
    if highest_severity_val == 1: subject_severity_prefix = "[LOW Alert]"
    elif highest_severity_val == 2: subject_severity_prefix = "[MEDIUM Alert]"
    elif highest_severity_val == 3: subject_severity_prefix = "[HIGH Alert]"
    elif highest_severity_val >= 4: subject_severity_prefix = "[CRITICAL Alert]"
        
    return subject_severity_prefix, email_body

def send_consolidated_email_notification(subject_prefix, formatted_vulnerabilities_body):
    # Ensure config is up-to-date before sending
    current_email_config = load_email_config() # Re-load config to get latest values

    if not is_user_subscribed(): # is_user_subscribed will use the re-loaded config
        print("[EmailNotifier SKIPPED] User is unsubscribed. No email sent.", file=sys.stderr)
        return True 

    # Use re-loaded config values for sending
    smtp_server = current_email_config.get("smtp_server")
    smtp_port = current_email_config.get("smtp_port")
    smtp_user = current_email_config.get("smtp_user")
    smtp_password = current_email_config.get("smtp_password")
    recipient_email = current_email_config.get("recipient_email")

    if not all([smtp_server, smtp_port, smtp_user, smtp_password, recipient_email]):
        print("[EmailNotifier SKIPPED] Email configuration is incomplete for consolidated email.", file=sys.stderr)
        print(f"    Subject Prefix: {subject_prefix}\n    Body Preview (first 200 chars): {formatted_vulnerabilities_body[:200]}...", file=sys.stderr)
        return False

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_subject = f"IoT Sentinel {subject_prefix}: Scan Report {timestamp}"

    unsubscribe_instruction = (
        f"\n\n---\nTo manage email notification preferences, please refer to the IoT Sentinel application "
        f"or contact your administrator. (Email: {recipient_email})"
    )
    final_body = formatted_vulnerabilities_body + unsubscribe_instruction

    msg = MIMEText(final_body, 'plain')
    msg['Subject'] = full_subject
    msg['From'] = smtp_user
    msg['To'] = recipient_email

    try:
        print(f"[EmailNotifier INFO] Attempting to send consolidated email to {recipient_email} via {smtp_server}:{smtp_port}", file=sys.stderr)
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, recipient_email, msg.as_string())
        print(f"[EmailNotifier SUCCESS] Consolidated email sent successfully to {recipient_email}", file=sys.stderr)
        return True
    except Exception as e:
        print(f"[EmailNotifier FAILED] Could not send consolidated email: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    # (Test code remains the same)
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
            ),
            ( # Test status message
                {"scanner": "test_scanner", "status": "scan_complete_no_issues_found", "ip": "10.0.0.99", "severity": "INFO"}, # Added severity for status
                "Status update from test_scanner",
                "scan_complete_no_issues_found"
            )
        ]
        if test_vulns_and_actions:
            subject_prefix, email_body = format_consolidated_vulnerabilities_for_email(test_vulns_and_actions)
            print("\n--- Sample Email Body ---")
            print(email_body)
            print("--- End Sample Email Body ---\n")
            send_consolidated_email_notification(subject_prefix, email_body)
