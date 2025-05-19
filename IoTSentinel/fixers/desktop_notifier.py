# /home/mininet/IoTSentinel/fixers/desktop_notifier.py
import subprocess
import sys
import os

# Ensure notify-send is available
NOTIFY_SEND_COMMAND = "notify-send"

def is_notify_send_available():
    """Checks if notify-send command is available."""
    try:
        subprocess.run([NOTIFY_SEND_COMMAND, "--version"], capture_output=True, check=True, text=True)
        print("[DesktopNotifier INFO] notify-send command is available.", file=sys.stderr)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[DesktopNotifier WARNING] notify-send command not found or not executable.", file=sys.stderr)
        print("    Please install it (e.g., 'sudo apt-get install libnotify-bin') for desktop notifications.", file=sys.stderr)
        return False

_notify_send_available = is_notify_send_available()

def send_desktop_notification(summary, body="", urgency="normal", icon_name=None):
    """
    Sends a desktop notification using notify-send.

    Args:
        summary (str): The title/summary of the notification.
        body (str, optional): The detailed body of the notification. Defaults to "".
        urgency (str, optional): Urgency level ('low', 'normal', 'critical'). Defaults to "normal".
        icon_name (str, optional): Name of an icon to display (e.g., 'dialog-warning', 'security-high').
                                   Can also be a full path to an image. Defaults to None.
    Returns:
        bool: True if the notification was likely sent, False otherwise.
    """
    if not _notify_send_available:
        print("[DesktopNotifier SKIPPED] notify-send not available.", file=sys.stderr)
        print(f"    Summary: {summary}\n    Body: {body}", file=sys.stderr)
        return False

    command = [NOTIFY_SEND_COMMAND, f"--urgency={urgency}"]
    
    if icon_name:
        command.extend(["--icon", icon_name])
    
    command.append(summary)
    if body: # notify-send treats the second non-option argument as the body
        command.append(body)

    try:
        print(f"[DesktopNotifier DEBUG] Executing command: {' '.join(command)}", file=sys.stderr)
        subprocess.run(command, check=True, text=True, capture_output=True)
        print(f"[DesktopNotifier SUCCESS] Sent notification: '{summary}'", file=sys.stderr)
        return True
    except FileNotFoundError: # Should be caught by _notify_send_available, but as a fallback
        print("[DesktopNotifier ERROR] notify-send command not found during execution.", file=sys.stderr)
        _notify_send_available = False # Update status
        return False
    except subprocess.CalledProcessError as e:
        print(f"[DesktopNotifier ERROR] Failed to send notification with notify-send: {e}", file=sys.stderr)
        if e.stderr:
            print(f"    notify-send stderr: {e.stderr}", file=sys.stderr)
        if e.stdout:
            print(f"    notify-send stdout: {e.stdout}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[DesktopNotifier ERROR] An unexpected error occurred: {e}", file=sys.stderr)
        return False

def format_vulnerability_message_for_desktop(scan_result_data, action_taken="None", action_outcome="N/A"):
    """
    Formats a summary and body for desktop notification.
    scan_result_data is the parsed JSON from the scanner.
    """
    ip = scan_result_data.get('ip', 'N/A')
    vuln_type = scan_result_data.get('vulnerability', 'Unknown Vulnerability')
    ports = scan_result_data.get('ports', scan_result_data.get('port', 'N/A'))
    severity = str(scan_result_data.get('severity', 'N/A')).upper()
    details = scan_result_data.get('details', 'No additional details.')

    summary = f"IoT Sentinel: [{severity}] {vuln_type} on {ip}"
    
    body = f"Device IP: {ip}\n"
    if ports != 'N/A':
        body += f"Port(s): {str(ports)}\n"
    body += f"Details: {details}\n\n"
    body += f"Fixer Action: {action_taken}\n"
    body += f"Outcome: {action_outcome}"
    
    icon = "dialog-warning" # Default icon
    urgency_level = "normal"
    if severity == "CRITICAL" or severity == "HIGH":
        icon = "security-high" # Or system-error, error
        urgency_level = "critical"
    elif severity == "MEDIUM":
        icon = "security-medium" # Or system-warning, warning
        urgency_level = "normal"
    elif severity == "LOW":
        icon = "security-low" # Or dialog-information, info
        urgency_level = "low"
        
    return summary, body, urgency_level, icon

# Example usage (for direct testing of this script)
if __name__ == "__main__":
    print("[DesktopNotifier Direct Test] Running direct test...", file=sys.stderr)
    
    # Test basic notification
    send_desktop_notification("Test Notification", "This is a test body from desktop_notifier.py.", urgency="low", icon_name="info")

    # Simulate a scan result
    example_scan_result = {
        "scanner": "ssh_weak_creds_scanner",
        "ip": "10.0.0.3",
        "vulnerability": "weak_ssh_credentials",
        "port": 22,
        "username": "user",
        "found_password": "password", 
        "details": "Weak SSH credentials found for user 'user' on 10.0.0.3.",
        "severity": "high"
    }
    
    summary, body, urgency, icon = format_vulnerability_message_for_desktop(
        example_scan_result,
        action_taken="Attempted to change SSH password for user 'user'.",
        action_outcome="Success (Simulated)"
    )
    send_desktop_notification(summary, body, urgency, icon)

    example_scan_result_telnet = {
        "scanner": "iot_port_scanner",
        "ip": "10.0.0.2",
        "vulnerability": "open_telnet_port",
        "ports": [23],
        "details": "Device 10.0.0.2 has open Telnet port 23.",
        "severity": "critical"
    }
    summary, body, urgency, icon = format_vulnerability_message_for_desktop(
        example_scan_result_telnet,
        action_taken="Attempted to disable Telnet service.",
        action_outcome="Failed - Simulated permission denied."
    )
    send_desktop_notification(summary, body, urgency, icon)
