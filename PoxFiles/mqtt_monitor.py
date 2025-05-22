# /home/mininet/pox/pox/misc/mqtt_monitor.py
import sys
import os
import subprocess
import threading
import json
import time 

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp 
from pox.lib.packet.icmp import icmp 
from pox.lib.util import dpid_to_str, str_to_bool

# --- Path Setup ---
try:
    pox_base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
    iot_sentinel_controllers_path = os.path.join(pox_base_dir, "IoTSentinel/controllers")
    iot_sentinel_scanners_path = os.path.join(pox_base_dir, "IoTSentinel/scanners")
    iot_sentinel_fixers_path = os.path.join(pox_base_dir, "IoTSentinel/fixers")

    for p_path in [iot_sentinel_controllers_path, iot_sentinel_fixers_path, iot_sentinel_scanners_path]:
        if p_path not in sys.path:
            sys.path.append(p_path)
except Exception as e:
    print(f"[mqtt_monitor CRITICAL] Error setting up sys.path: {e}", file=sys.stderr)
    raise

# --- Module Imports ---
try:
    from acl import ACLManager
    from fwd_table import ForwardingTableManager
    from email_notifier import send_consolidated_email_notification, format_consolidated_vulnerabilities_for_email, update_user_unsubscribe_status, is_user_subscribed
except ModuleNotFoundError as e:
    print(f"[mqtt_monitor CRITICAL] Failed to import IoTSentinel modules. Error: {e}", file=sys.stderr)
    if 'send_consolidated_email_notification' not in globals():
        def send_consolidated_email_notification(subject_prefix, body):
            print(f"[DUMMY_EMAIL_ALERT] Email Notifier not loaded. Subject: {subject_prefix}\nBody:\n{body}", file=sys.stderr)
            return False
        def format_consolidated_vulnerabilities_for_email(vulnerabilities_with_actions):
            return "[INFO] (Email N/A)", f"Scan Data (Email N/A): {vulnerabilities_with_actions}"
        def is_user_subscribed(): return False
        def update_user_unsubscribe_status(s): pass
        print("[mqtt_monitor WARNING] Email notifier functions could not be imported. Using dummies.", file=sys.stderr)
    if "ACLManager" not in globals() or "ForwardingTableManager" not in globals():
        raise 
except ImportError as e: 
    print(f"[mqtt_monitor WARNING] ImportError for some modules: {e}. Using dummies where applicable.", file=sys.stderr)
    if 'send_consolidated_email_notification' not in globals():
        def send_consolidated_email_notification(subject_prefix, body):
             print(f"[DUMMY_EMAIL_ALERT] Email Notifier not loaded. Subject: {subject_prefix}\nBody:\n{body}", file=sys.stderr)
             return False
        def format_consolidated_vulnerabilities_for_email(vulnerabilities_with_actions):
            return "[INFO] (Email N/A)", f"Scan Data (Email N/A): {vulnerabilities_with_actions}"
        def is_user_subscribed(): return False
        def update_user_unsubscribe_status(s): pass

log = core.getLogger()

acl_manager = ACLManager()
fwd_table_manager = ForwardingTableManager()

_network_fully_up = False
_scan_timer = None
_initial_scan_delay_seconds = 15 
_scan_interval_seconds = 60    

_current_scan_cycle_results = [] 
_scan_cycle_lock = threading.Lock() 

_external_scanners_dispatched = 0
_external_scanners_completed = 0
_fixers_dispatched_this_cycle = 0
_fixers_completed_this_cycle = 0
_scan_cycle_active = False 

DOS_WINDOW_SECONDS = 10
SYN_FLOOD_THRESHOLD = 50 
CONNECTION_RATE_THRESHOLD = 100 
UDP_PACKET_RATE_THRESHOLD = 200 
ICMP_PACKET_RATE_THRESHOLD = 50 

syn_tracker = {}            
connection_tracker = {}     
udp_flood_tracker = {}      
icmp_flood_tracker = {}     
dos_alert_cooldown = {}     
DOS_ALERT_COOLDOWN_SECONDS = 120 

dos_state_lock = threading.Lock() 
dos_cleanup_timer = None
DOS_CLEANUP_INTERVAL = DOS_WINDOW_SECONDS * 2


def _is_on_cooldown(vuln_type, target_ip, target_port=None):
    key = (vuln_type, target_ip, target_port)
    last_alert_time = dos_alert_cooldown.get(key)
    if last_alert_time and (time.time() - last_alert_time) < DOS_ALERT_COOLDOWN_SECONDS:
        return True
    return False

def _set_cooldown(vuln_type, target_ip, target_port=None):
    key = (vuln_type, target_ip, target_port)
    dos_alert_cooldown[key] = time.time()

def _check_if_scan_cycle_fully_complete():
    global _scan_cycle_active, _external_scanners_dispatched, _external_scanners_completed
    global _fixers_dispatched_this_cycle, _fixers_completed_this_cycle

    with _scan_cycle_lock:
        if not _scan_cycle_active:
            return

        scanners_done = (_external_scanners_completed >= _external_scanners_dispatched)
        fixers_done = (_fixers_completed_this_cycle >= _fixers_dispatched_this_cycle)

        log.debug(f"[SYNC_CHECK] Scanners: {_external_scanners_completed}/{_external_scanners_dispatched}. Fixers: {_fixers_completed_this_cycle}/{_fixers_dispatched_this_cycle}.")

        if scanners_done and fixers_done:
            log.info("[SYNC_CHECK] All dispatched scanners and fixers for this cycle have completed.")
            core.callLater(finalize_scan_cycle_reporting) 
            _scan_cycle_active = False 
        else:
            log.debug("[SYNC_CHECK] Scan cycle not yet fully complete. Waiting for more components.")

def finalize_scan_cycle_reporting():
    global _current_scan_cycle_results 
    with _scan_cycle_lock:
        log.info(f"[FINALIZE_REPORT] Generating report. Found {len(_current_scan_cycle_results)} items for this cycle.")
        
        subject_prefix, email_body = format_consolidated_vulnerabilities_for_email(_current_scan_cycle_results or [])
        send_consolidated_email_notification(subject_prefix, email_body)
        
        _current_scan_cycle_results = [] 
        log.debug("[FINALIZE_REPORT] Scan results cleared.")

def _external_scanner_completed_callback():
    global _external_scanners_completed
    with _scan_cycle_lock: 
        _external_scanners_completed += 1
        log.debug(f"[SCANNER_CB] External scanner completed. Total: {_external_scanners_completed}/{_external_scanners_dispatched}")
    _check_if_scan_cycle_fully_complete() 

def _fixer_thread_completed_callback():
    global _fixers_completed_this_cycle
    with _scan_cycle_lock: 
        _fixers_completed_this_cycle += 1
        log.debug(f"[FIXER_CB] Fixer thread completed. Total: {_fixers_completed_this_cycle}/{_fixers_dispatched_this_cycle}")
    _check_if_scan_cycle_fully_complete() 

def _execute_scanner_threaded(scanner_name, command):
    log.info(f"[SCANNER_THREAD] Starting external scanner: {scanner_name} with command: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=180)
        if result.stdout and result.stdout.strip():
            log.debug(f"[SCANNER_THREAD_STDOUT] {scanner_name}:\n{result.stdout.strip()}")
            core.callLater(process_scanner_output, scanner_name, result.stdout.strip())
        else:
            log.info(f"[SCANNER_THREAD] {scanner_name} produced NO STDOUT.")
        if result.stderr and result.stderr.strip():
            log.info(f"[SCANNER_THREAD_STDERR] {scanner_name}:\n{result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        log.error(f"[SCANNER_THREAD_TIMEOUT] {scanner_name} timed out.")
        with _scan_cycle_lock:
            _current_scan_cycle_results.append(
                ({"scanner": scanner_name, "vulnerability": "scanner_timeout", "ip": "N/A", "details": f"{scanner_name} timed out.", "severity":"ERROR"}, 
                 f"Execution of {scanner_name}", "Timed out")
            )
    except Exception as e:
        log.error(f"[SCANNER_THREAD_EXCEPTION] Error running {scanner_name}: {e}", exc_info=True)
        with _scan_cycle_lock:
            _current_scan_cycle_results.append(
                ({"scanner": scanner_name, "vulnerability": "scanner_error", "ip": "N/A", "details": f"Error running {scanner_name}: {e}", "severity":"ERROR"}, 
                 f"Execution of {scanner_name}", f"Failed with exception: {e}")
            )
    finally:
        core.callLater(_external_scanner_completed_callback) 

def run_scanners(): 
    global _external_scanners_dispatched, _external_scanners_completed
    global _fixers_dispatched_this_cycle, _fixers_completed_this_cycle
    global _scan_cycle_active, _current_scan_cycle_results

    with _scan_cycle_lock:
        if _scan_cycle_active:
            log.warning("[SCANNER_DISPATCH] New scan cycle initiated while previous one might still be finalizing related fixers.")
        
        log.info("[SCANNER_DISPATCH] Starting new full scan cycle (external scanners + potential fixers).")
        _external_scanners_dispatched = 0
        _external_scanners_completed = 0
        _fixers_dispatched_this_cycle = 0 
        _fixers_completed_this_cycle = 0
        _scan_cycle_active = True 
        _current_scan_cycle_results = [] 

    scanners_to_run = {
        "iot_port_scanner": ["python3", os.path.join(iot_sentinel_scanners_path, "iot_scanner.py")],
        "ssh_scanner": ["python3", os.path.join(iot_sentinel_scanners_path, "ssh_scanner.py")]
    }

    if not scanners_to_run:
        log.info("[SCANNER_DISPATCH] No external scanners configured.")
        _scan_cycle_active = False 
        _check_if_scan_cycle_fully_complete() 
        return

    _external_scanners_dispatched = len(scanners_to_run)
    log.debug(f"[SCANNER_DISPATCH] Expecting {_external_scanners_dispatched} external scanner threads for this cycle.")

    if _external_scanners_dispatched == 0: 
        log.info("[SCANNER_DISPATCH] No external scanner threads to launch.")
        _scan_cycle_active = False
        _check_if_scan_cycle_fully_complete()
        return

    for scanner_name, command in scanners_to_run.items():
        thread = threading.Thread(target=_execute_scanner_threaded, args=(scanner_name, command), daemon=True)
        thread.start()
        log.debug(f"[SCANNER_DISPATCH] External scanner thread launched for {scanner_name}")
    
def _execute_fixer_threaded(fixer_name, command_args, original_scan_result_data):
    global _current_scan_cycle_results, acl_manager
    
    if fixer_name == "ddos_fixer":
        full_command = ["python3", os.path.join(iot_sentinel_fixers_path, fixer_name + ".py"), command_args[0]]
    else:
        full_command = ["python3", os.path.join(iot_sentinel_fixers_path, fixer_name + ".py")] + command_args
        
    log_command = list(full_command) 
    if 'found_password' in original_scan_result_data and original_scan_result_data.get('found_password') and original_scan_result_data['found_password'] in log_command:
        try:
            idx = log_command.index(original_scan_result_data['found_password'])
            log_command[idx] = '********'
        except ValueError: pass 
    elif fixer_name == 'port_closer' and len(log_command) > 4 and len(command_args) > 3: 
        if len(log_command) > 6: log_command[6] = '********'

    log.info(f"[FIXER_THREAD] Starting: {fixer_name} for IP {original_scan_result_data.get('ip')} with command: {' '.join(log_command)}")
    action_description = f"Ran fixer '{fixer_name}' for IP '{original_scan_result_data.get('ip', 'N/A')}'"
    if "username" in original_scan_result_data and fixer_name != "ddos_fixer":
        action_description += f" user '{original_scan_result_data['username']}'"
    
    outcome_message = f"Fixer script '{fixer_name}' execution resulted in an unknown state." 
    fix_successful = False 

    try:
        result = subprocess.run(full_command, capture_output=True, text=True, check=False, timeout=180)
        log.debug(f"[FIXER_THREAD_RAW_RESULT] {fixer_name} (Target IP: {original_scan_result_data.get('ip')}) - RC: {result.returncode}")

        if result.stdout and result.stdout.strip():
            log.debug(f"[FIXER_THREAD_STDOUT] {fixer_name}:\n{result.stdout.strip()}")
            try:
                parsed_fixer_json = json.loads(result.stdout.strip())
                fix_successful = parsed_fixer_json.get("success", False)
                outcome_message = parsed_fixer_json.get("message", f"Fixer '{fixer_name}' provided no detailed message.")

                if fixer_name == "ssh_fixer" and fix_successful:
                    new_password = parsed_fixer_json.get("new_password_generated")
                    if new_password:
                        # Append the new password to the outcome_message that will be stored
                        outcome_message += f" The new password set is: {new_password}"
                    else:
                        outcome_message += " (New password was expected but not found in fixer output)."
                
                elif fixer_name == "ddos_fixer" and fix_successful:
                    ips_to_block = parsed_fixer_json.get("ips_suggested_for_blocking", [])
                    blocked_details_list = []
                    if ips_to_block:
                        for ip_to_block in ips_to_block:
                            log.info(f"[DDOS_MITIGATION] POX ACL: Attempting to DENY traffic from source IP: {ip_to_block} (related to attack on {original_scan_result_data.get('ip')})")
                            acl_manager.add_rule(ip_to_block, "ANY", 6, action="deny")  
                            acl_manager.add_rule(ip_to_block, "ANY", 17, action="deny") 
                            acl_manager.add_rule(ip_to_block, "ANY", 1, action="deny")  
                            blocked_details_list.append(f"Denied source IP {ip_to_block} (TCP/UDP/ICMP)")
                        if blocked_details_list:
                            outcome_message = f"ddos_fixer suggested blocking. POX applied network ACLs: {'; '.join(blocked_details_list)}"
                        else:
                            outcome_message += " However, POX ACL component did not action any specific IP blocks from suggestions."
                    else: 
                        outcome_message = f"ddos_fixer reported success but no specific IPs were suggested for blocking for target {original_scan_result_data.get('ip')}."
                
            except json.JSONDecodeError:
                log.error(f"[FIXER_THREAD_JSON_ERROR] Could not parse JSON from {fixer_name}: {result.stdout.strip()}", exc_info=True)
                outcome_message = f"Fixer script '{fixer_name}' output was not valid JSON."
                fix_successful = False 
        else: 
            log.info(f"[FIXER_THREAD] {fixer_name} produced NO STDOUT. RC: {result.returncode}")
            outcome_message = f"Fixer script '{fixer_name}' produced no standard output. Return Code: {result.returncode}."
            if result.returncode != 0 : fix_successful = False 
            
        if result.stderr and result.stderr.strip():
            log.info(f"[FIXER_THREAD_STDERR] {fixer_name}:\n{result.stderr.strip()}")
            if not (result.stdout and result.stdout.strip()): 
                 outcome_message += f" (Stderr: {result.stderr.strip()})"
            if result.returncode !=0 and fix_successful:
                log.warning(f"Fixer {fixer_name} claimed success but had non-zero RC ({result.returncode}) and stderr. Considering it failed.")
                fix_successful = False

        if fixer_name == "port_closer" and not fix_successful:
            target_ip_for_acl = original_scan_result_data.get("ip")
            port_for_acl_str = command_args[1] if len(command_args) > 1 else None
            proto_str = command_args[2] if len(command_args) > 2 else None
            
            if port_for_acl_str and proto_str:
                try:
                    port_for_acl = int(port_for_acl_str)
                    proto_for_acl = 6 if proto_str.lower() == "tcp" else 17 if proto_str.lower() == "udp" else None
                    if target_ip_for_acl and proto_for_acl:
                        log.info(f"[NET_ACL_FIX] On-device 'port_closer' failed or did not confirm closure for {target_ip_for_acl}:{port_for_acl}/{proto_str}. Applying POX network ACL to block port.")
                        acl_manager.add_rule(target_ip_for_acl, port_for_acl, proto_for_acl, action="deny") 
                        outcome_message += f" POX additionally applied a network ACL to block incoming traffic to port {port_for_acl}/{proto_str} on {target_ip_for_acl}."
                except ValueError:
                    log.error(f"[NET_ACL_FIX] Could not parse port '{port_for_acl_str}' for network ACL for {target_ip_for_acl}.")

        log_level = log.info if fix_successful else log.warning
        log_level(f"[FIXER_OUTCOME] Fixer '{fixer_name}' for IP '{original_scan_result_data.get('ip', 'N/A')}' reported: Success={fix_successful}, Message='{outcome_message}'")

    except subprocess.TimeoutExpired:
        log.error(f"[FIXER_THREAD_TIMEOUT] {fixer_name} timed out.")
        outcome_message = f"Fixer script '{fixer_name}' timed out."
        fix_successful = False
    except FileNotFoundError:
        log.error(f"[FIXER_THREAD_ERROR] Script not found for {fixer_name}: {full_command[1]}")
        outcome_message = f"Fixer script '{fixer_name}.py' not found."
        fix_successful = False
    except Exception as e:
        log.error(f"[FIXER_THREAD_EXCEPTION] Error running {fixer_name}: {e}", exc_info=True)
        outcome_message = f"Exception running fixer '{fixer_name}': {str(e)}"
        fix_successful = False
    
    with _scan_cycle_lock:
        _current_scan_cycle_results.append(
            (original_scan_result_data, action_description, outcome_message)
        )
    
    core.callLater(_fixer_thread_completed_callback)

def orchestrate_fixer(scan_result_data):
    global _fixers_dispatched_this_cycle, _scan_cycle_lock 
    
    vuln_type = scan_result_data.get("vulnerability")
    ip = scan_result_data.get("ip") 

    if not vuln_type or not ip:
        log.warning("[FIXER_ORCHESTRATOR] Vuln type or IP missing in scan_result_data. Cannot orchestrate fix.")
        if scan_result_data.get("scanner") != "pox_internal_dos_detector":
            with _scan_cycle_lock:
                _current_scan_cycle_results.append(
                    (scan_result_data, "Fixer Orchestration Skipped", "Incomplete scan data (missing type or IP).")
                )
        return

    log.info(f"[FIXER_ORCHESTRATOR] Vulnerability: '{vuln_type}' on target IP {ip}. Deciding on fixer.")

    fixer_name = None
    fixer_args = []
    action_desc_if_no_fixer = f"Identified '{vuln_type}' on {ip}."
    outcome_if_no_fixer = "No specific automated fixer action taken/configured for this type."

    if vuln_type == "weak_ssh_credentials":
        username = scan_result_data.get("username")
        old_password = scan_result_data.get("found_password") 
        if username and old_password is not None: 
            fixer_name = "ssh_fixer"
            fixer_args = [ip, username, old_password]
        else: 
            log.warning(f"[FIXER_ORCHESTRATOR] Username or old_password missing for weak_ssh_credentials on {ip}.")
            with _scan_cycle_lock: _current_scan_cycle_results.append((scan_result_data, f"Fix attempt for weak SSH on {ip}", "Failed: Missing username/password from scan data."))
            return 
            
    elif vuln_type == "open_telnet_port" or \
         (vuln_type == "open_ports" and 23 in scan_result_data.get("ports",[])):
        fixer_name = "port_closer"
        ssh_user = scan_result_data.get("ssh_user", "user") 
        ssh_pass = scan_result_data.get("ssh_pass", "password")
        fixer_args = [ip, "23", "tcp", ssh_user, ssh_pass]
        log.info(f"[FIXER_ORCHESTRATOR] Detected open Telnet on {ip}. Attempting to close port 23/tcp via port_closer using SSH user '{ssh_user}'.")
            
    elif (vuln_type == "open_ports" and 80 in scan_result_data.get("ports", []) and ip != "10.0.0.100"):
        fixer_name = "port_closer"
        ssh_user = scan_result_data.get("ssh_user", "user")
        ssh_pass = scan_result_data.get("ssh_pass", "password")
        fixer_args = [ip, "80", "tcp", ssh_user, ssh_pass]
        log.info(f"[FIXER_ORCHESTRATOR] Detected open HTTP (port 80) on non-broker {ip}. Attempting to close via port_closer using SSH user '{ssh_user}'.")

    elif vuln_type == "firmware_vulnerable": 
        firmware_url = scan_result_data.get("update_url")
        if firmware_url:
            fixer_name = "firmware_updater"
            fixer_args = [ip, firmware_url]
        else: 
            log.warning(f"[FIXER_ORCHESTRATOR] Firmware update URL missing for {ip}.")
            with _scan_cycle_lock: _current_scan_cycle_results.append((scan_result_data, f"Fix attempt for firmware on {ip}", "Failed: Missing firmware URL."))
            return

    elif vuln_type in ["potential_syn_flood", "potential_connection_flood", "potential_udp_flood", "potential_icmp_flood", "potential_dos_ddos_attack"]:
        fixer_name = "ddos_fixer"
        fixer_args = [json.dumps(scan_result_data)] 
        log.info(f"[FIXER_ORCHESTRATOR] Potential DoS/DDoS event '{vuln_type}' on {ip}. Dispatching ddos_fixer.")
    
    elif vuln_type == "open_ports": 
        ports = scan_result_data.get("ports", [])
        log.info(f"[FIXER_ORCHESTRATOR] Generic open_ports {ports} on {ip}. No specific auto-fixer beyond Telnet/HTTP rules above.")
        with _scan_cycle_lock: _current_scan_cycle_results.append((scan_result_data, action_desc_if_no_fixer.replace("'{vuln_type}'", f"open port(s) {ports}"), outcome_if_no_fixer))
        return
    else: 
        log.info(f"[FIXER_ORCHESTRATOR] No fixer defined for vulnerability type: '{vuln_type}' on {ip}.")
        with _scan_cycle_lock: _current_scan_cycle_results.append((scan_result_data, action_desc_if_no_fixer, outcome_if_no_fixer))
        return

    if fixer_name:
        with _scan_cycle_lock: 
            _fixers_dispatched_this_cycle += 1
            log.debug(f"[FIXER_ORCHESTRATOR] Fixer '{fixer_name}' for IP '{ip}' dispatched. Expected fixers now: {_fixers_dispatched_this_cycle}")

        log_args_display = [] 
        if fixer_name == "ssh_fixer" and len(fixer_args) > 2: log_args_display = [fixer_args[0], fixer_args[1], "********"]
        elif fixer_name == "port_closer" and len(fixer_args) > 4: log_args_display = fixer_args[:3] + [fixer_args[3], "********"]
        elif fixer_name == "ddos_fixer": log_args_display = ["<scan_data_json>"]
        else: log_args_display = fixer_args

        log.info(f"[FIXER_ORCHESTRATOR] Dispatching fixer '{fixer_name}' for IP '{ip}' with args: {log_args_display}")
        thread = threading.Thread(target=_execute_fixer_threaded, args=(fixer_name, fixer_args, scan_result_data), daemon=True)
        thread.start()
    else:
        pass

def process_scanner_output(scanner_name, output_str):
    log.info(f"[PROCESS_SCANNER] Processing output from external scanner: {scanner_name}...")
    lines = output_str.strip().split('\n')
    if not lines or not output_str.strip():
        log.info(f"[PROCESS_SCANNER] No content from {scanner_name}.")
        return

    vulnerabilities_processed_from_this_scanner = 0
    for line_num, line in enumerate(lines):
        line = line.strip()
        if not line: continue
        try:
            data = json.loads(line)
            if data.get("status"): 
                log.info(f"[SCANNER_STATUS] {scanner_name}: {data.get('status')} (Targets: {data.get('targets_checked', 'N/A')})")
                with _scan_cycle_lock: 
                    _current_scan_cycle_results.append(
                        (data, f"Status update from {scanner_name}", data.get('status'))
                    )
                continue 
            
            log.warning(f"[VULN_DETECTED] Source: {scanner_name}, Type: {data.get('vulnerability','N/A')}, IP: {data.get('ip','N/A')}, Severity: {str(data.get('severity','N/A')).upper()}")
            orchestrate_fixer(data) 
            vulnerabilities_processed_from_this_scanner +=1
            
        except json.JSONDecodeError:
            log.error(f"[PROCESS_SCANNER_JSON_ERROR] JSONDecodeError from {scanner_name}: '{line}'", exc_info=True)
        except Exception as e:
            log.error(f"[PROCESS_SCANNER_ERROR] General error processing output from {scanner_name}: {e} - Data: '{line}'", exc_info=True)
    
    if vulnerabilities_processed_from_this_scanner == 0 and not any(json.loads(l).get("status") for l in lines if l.strip()):
        log.info(f"[PROCESS_SCANNER] Scanner {scanner_name} finished but reported no specific vulnerabilities or status messages in its JSON output.")

def _handle_PacketIn(event):
    global syn_tracker, connection_tracker, udp_flood_tracker, icmp_flood_tracker, dos_state_lock, dos_alert_cooldown, _current_scan_cycle_results
    global _fixers_dispatched_this_cycle 
    packet = event.parsed
    if not packet.parsed: return

    eth_packet = packet.find(ethernet) 
    if not eth_packet: return

    ip_packet = packet.find(ipv4)
    if not ip_packet: return

    tcp_packet = packet.find(tcp)
    udp_packet = packet.find(udp)
    icmp_payload = packet.find(icmp) 

    current_time = time.time()
    dst_ip_str = str(ip_packet.dstip)
    src_ip_str = str(ip_packet.srcip)

    with dos_state_lock: 
        if tcp_packet and tcp_packet.SYN and not tcp_packet.ACK:
            target_port = tcp_packet.dstport
            if not _is_on_cooldown("potential_syn_flood", dst_ip_str, target_port):
                key = (dst_ip_str, target_port)
                if key not in syn_tracker: syn_tracker[key] = {}
                syn_tracker[key][src_ip_str] = current_time
                
                active_syn_sources = {s: ts for s, ts in syn_tracker[key].items() if current_time - ts <= DOS_WINDOW_SECONDS}
                syn_tracker[key] = active_syn_sources
                
                if len(active_syn_sources) > SYN_FLOOD_THRESHOLD:
                    log.critical(f"[DOS_DETECTED] Potential SYN Flood on {dst_ip_str}:{target_port} from {len(active_syn_sources)} sources!")
                    _set_cooldown("potential_syn_flood", dst_ip_str, target_port)
                    vuln_data = {"scanner": "pox_internal_dos_detector", "ip": dst_ip_str, "vulnerability": "potential_syn_flood",
                                 "details": f"SYN flood: {len(active_syn_sources)} SYNs to port {target_port} in {DOS_WINDOW_SECONDS}s.",
                                 "port": target_port, "protocol": "TCP",
                                 "prominent_sources": [{"ip": s} for s in list(active_syn_sources.keys())[:10]], "severity": "critical"}
                    with _scan_cycle_lock: 
                        _current_scan_cycle_results.append((vuln_data, f"Internal DoS Detection: SYN Flood on {dst_ip_str}:{target_port}", "Threshold breached, attempting mitigation via ddos_fixer."))
                    core.callLater(orchestrate_fixer, vuln_data) 
                    syn_tracker[key] = {} 

        if tcp_packet and tcp_packet.SYN: 
            if not _is_on_cooldown("potential_connection_flood", dst_ip_str):
                if dst_ip_str not in connection_tracker: connection_tracker[dst_ip_str] = {}
                connection_tracker[dst_ip_str][src_ip_str] = current_time
                active_connections = {s: ts for s, ts in connection_tracker[dst_ip_str].items() if current_time - ts <= DOS_WINDOW_SECONDS}
                connection_tracker[dst_ip_str] = active_connections
                if len(active_connections) > CONNECTION_RATE_THRESHOLD:
                    log.critical(f"[DOS_DETECTED] High connection rate to {dst_ip_str} from {len(active_connections)} sources!")
                    _set_cooldown("potential_connection_flood", dst_ip_str)
                    vuln_data = {"scanner": "pox_internal_dos_detector", "ip": dst_ip_str, "vulnerability": "potential_connection_flood",
                                 "details": f"High connection rate: {len(active_connections)} sources attempting connection in {DOS_WINDOW_SECONDS}s.",
                                 "prominent_sources": [{"ip": s} for s in list(active_connections.keys())[:10]], "severity": "critical"}
                    with _scan_cycle_lock:
                        _current_scan_cycle_results.append((vuln_data, f"Internal DoS Detection: Connection Flood on {dst_ip_str}", "Threshold breached, attempting mitigation via ddos_fixer."))
                    core.callLater(orchestrate_fixer, vuln_data)
                    connection_tracker[dst_ip_str] = {}

        if udp_packet:
            target_port = udp_packet.dstport
            if not _is_on_cooldown("potential_udp_flood", dst_ip_str, target_port):
                key = (dst_ip_str, target_port)
                if key not in udp_flood_tracker: udp_flood_tracker[key] = {"count": 0, "window_start_time": current_time, "sources": {}}
                
                if current_time - udp_flood_tracker[key]["window_start_time"] > DOS_WINDOW_SECONDS:
                    udp_flood_tracker[key] = {"count": 0, "window_start_time": current_time, "sources": {}} 
                
                udp_flood_tracker[key]["count"] += 1
                udp_flood_tracker[key]["sources"][src_ip_str] = udp_flood_tracker[key]["sources"].get(src_ip_str, 0) + 1

                if udp_flood_tracker[key]["count"] > UDP_PACKET_RATE_THRESHOLD:
                    log.critical(f"[DOS_DETECTED] Potential UDP Flood on {dst_ip_str}:{target_port} - {udp_flood_tracker[key]['count']} packets.")
                    _set_cooldown("potential_udp_flood", dst_ip_str, target_port)
                    top_sources = sorted(udp_flood_tracker[key]["sources"].items(), key=lambda item: item[1], reverse=True)[:5]
                    vuln_data = {"scanner": "pox_internal_dos_detector", "ip": dst_ip_str, "vulnerability": "potential_udp_flood",
                                 "details": f"UDP flood: {udp_flood_tracker[key]['count']} packets to port {target_port}.",
                                 "port": target_port, "protocol": "UDP", "packet_count": udp_flood_tracker[key]['count'],
                                 "prominent_sources": [{"ip": s[0], "count":s[1]} for s in top_sources], "severity": "critical"}
                    with _scan_cycle_lock:
                        _current_scan_cycle_results.append((vuln_data, f"Internal DoS Detection: UDP Flood on {dst_ip_str}:{target_port}", "Threshold breached, attempting mitigation via ddos_fixer."))
                    core.callLater(orchestrate_fixer, vuln_data)
                    del udp_flood_tracker[key] 

        if icmp_payload: 
            if not _is_on_cooldown("potential_icmp_flood", dst_ip_str):
                if dst_ip_str not in icmp_flood_tracker: icmp_flood_tracker[dst_ip_str] = {"count": 0, "window_start_time": current_time, "sources": {}}

                if current_time - icmp_flood_tracker[dst_ip_str]["window_start_time"] > DOS_WINDOW_SECONDS:
                    icmp_flood_tracker[dst_ip_str] = {"count": 0, "window_start_time": current_time, "sources": {}}

                icmp_flood_tracker[dst_ip_str]["count"] += 1
                icmp_flood_tracker[dst_ip_str]["sources"][src_ip_str] = icmp_flood_tracker[dst_ip_str]["sources"].get(src_ip_str, 0) + 1

                if icmp_flood_tracker[dst_ip_str]["count"] > ICMP_PACKET_RATE_THRESHOLD:
                    log.critical(f"[DOS_DETECTED] Potential ICMP Flood on {dst_ip_str} - {icmp_flood_tracker[dst_ip_str]['count']} packets.")
                    _set_cooldown("potential_icmp_flood", dst_ip_str)
                    top_sources = sorted(icmp_flood_tracker[dst_ip_str]["sources"].items(), key=lambda item: item[1], reverse=True)[:5]
                    vuln_data = {"scanner": "pox_internal_dos_detector", "ip": dst_ip_str, "vulnerability": "potential_icmp_flood",
                                 "details": f"ICMP flood: {icmp_flood_tracker[dst_ip_str]['count']} ICMP packets.",
                                 "protocol": "ICMP", "packet_count": icmp_flood_tracker[dst_ip_str]['count'],
                                 "prominent_sources": [{"ip": s[0], "count":s[1]} for s in top_sources], "severity": "critical"}
                    with _scan_cycle_lock:
                        _current_scan_cycle_results.append((vuln_data, f"Internal DoS Detection: ICMP Flood on {dst_ip_str}", "Threshold breached, attempting mitigation via ddos_fixer."))
                    core.callLater(orchestrate_fixer, vuln_data)
                    del icmp_flood_tracker[dst_ip_str]
    
    dst_port_for_acl = 0
    if tcp_packet: dst_port_for_acl = tcp_packet.dstport
    elif udp_packet: dst_port_for_acl = udp_packet.dstport
    
    pass_source_check = acl_manager.check_acl(src_ip_str, 0, ip_packet.protocol, direction="source") 
    pass_dest_check = acl_manager.check_acl(dst_ip_str, dst_port_for_acl, ip_packet.protocol, direction="destination") 

    if pass_source_check and pass_dest_check:
        is_interesting_log = False
        if tcp_packet and (dst_port_for_acl in [22,23,80,1883] or tcp_packet.srcport in [22,23,80,1883]):
            is_interesting_log = True
        elif icmp_payload:
            is_interesting_log = True
        
        if is_interesting_log: # Log only if interesting and passed ACL
             log.info(f"[ACL_PASS] Proto {ip_packet.protocol}: {src_ip_str}{(':' + str(tcp_packet.srcport)) if tcp_packet else ''} -> {dst_ip_str}{(':' + str(dst_port_for_acl)) if dst_port_for_acl else ''}")
        
        forwarding_entry = fwd_table_manager.get_next_hop(dst_ip_str)
        out_port = forwarding_entry.get("port") if forwarding_entry else None
        
        if out_port is not None:
            match = of.ofp_match.from_packet(packet, event.port)
            msg = of.ofp_flow_mod(command=of.OFPFC_ADD, match=match, idle_timeout=10, hard_timeout=30) 
            msg.actions.append(of.ofp_action_output(port=out_port))
            if event.ofp and event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None: 
                msg.buffer_id = event.ofp.buffer_id
            else:
                msg.data = event.ofp 
            event.connection.send(msg)
            if is_interesting_log: log.debug(f"[FLOW_MOD] FWD_TABLE: ALLOWED {src_ip_str} -> {dst_ip_str} to switch port {out_port}")
        else: # No static rule, let l2_learning handle it (if l2_learning is active)
            if is_interesting_log: log.debug(f"[FORWARDING] No static fwd rule for {dst_ip_str}. ACL passed. Relying on l2_learning or default switch behavior.")
            # If l2_learning is not loaded, or to be explicit for other cases:
            # Allow packet to be processed by other handlers / l2_learning by not returning event.halt
            pass 
    else: 
        log.warning(f"[ACL_BLOCK] TRAFFIC BLOCKED by ACL: {src_ip_str} -> {dst_ip_str} (Port:{dst_port_for_acl}, Proto:{ip_packet.protocol}). SrcOK:{pass_source_check}, DstOK:{pass_dest_check}")
        msg = of.ofp_flow_mod(command=of.OFPFC_ADD, match=of.ofp_match.from_packet(packet, event.port), idle_timeout=60, hard_timeout=120)
        event.connection.send(msg) # Install a drop rule
    return # Explicitly return to ensure no other handlers process a blocked packet if this was the intent.

def _cleanup_dos_trackers():
    global syn_tracker, connection_tracker, udp_flood_tracker, icmp_flood_tracker, dos_state_lock, dos_cleanup_timer, dos_alert_cooldown
    current_time = time.time()
    cleaned_count = 0
    with dos_state_lock:
        keys_to_delete_cooldown = [k for k, ts in list(dos_alert_cooldown.items()) if current_time - ts > DOS_ALERT_COOLDOWN_SECONDS * 1.5]
        for key in keys_to_delete_cooldown: del dos_alert_cooldown[key]; cleaned_count+=1
        
        for key, sources in list(syn_tracker.items()):
            active_sources = {src: ts for src, ts in sources.items() if current_time - ts <= DOS_WINDOW_SECONDS * 1.5}
            if not active_sources: del syn_tracker[key]; cleaned_count+=1
            else: syn_tracker[key] = active_sources

        for dst_ip, sources in list(connection_tracker.items()):
            active_connections = {src: ts for src, ts in sources.items() if current_time - ts <= DOS_WINDOW_SECONDS * 1.5}
            if not active_connections: del connection_tracker[dst_ip]; cleaned_count+=1
            else: connection_tracker[dst_ip] = active_connections
            
        keys_to_delete_udp = [k for k, data in list(udp_flood_tracker.items()) if current_time - data.get("window_start_time", 0) > DOS_WINDOW_SECONDS * 1.5]
        for key in keys_to_delete_udp: del udp_flood_tracker[key]; cleaned_count+=1

        keys_to_delete_icmp = [k for k, data in list(icmp_flood_tracker.items()) if current_time - data.get("window_start_time", 0) > DOS_WINDOW_SECONDS * 1.5]
        for key in keys_to_delete_icmp: del icmp_flood_tracker[key]; cleaned_count+=1
            
    if cleaned_count > 0:
        log.debug(f"[DOS_TRACKER_CLEANUP] Cleaned {cleaned_count} stale entries from DoS trackers/cooldowns.")
    dos_cleanup_timer = core.callDelayed(DOS_CLEANUP_INTERVAL, _cleanup_dos_trackers)

def _recurring_scanner_loop_task(interval_seconds_arg):
    global _scan_timer, _scan_cycle_active
    with _scan_cycle_lock:
        if _scan_cycle_active: 
            log.warning("[SCHEDULER_LOOP_RECURRING] Previous scan cycle may not have fully finalized (still active). Skipping this scheduled external scan to avoid overlap.")
            _scan_timer = core.callDelayed(interval_seconds_arg, _recurring_scanner_loop_task, interval_seconds_arg)
            return

    if _network_fully_up:
        run_scanners() 
    else:
        log.info("[SCHEDULER_LOOP_RECURRING] Network not up, skipping external scan cycle.")
    _scan_timer = core.callDelayed(interval_seconds_arg, _recurring_scanner_loop_task, interval_seconds_arg)
    log.info(f"[SCHEDULER] Next external scan cycle scheduled in {interval_seconds_arg}s.")

def _initial_scanner_task(interval_seconds_arg):
    global _scan_timer
    if _network_fully_up:
        run_scanners()
    else:
        log.info("[SCHEDULER_LOOP_INIT] Network not up, skipping first external scan cycle.")
    _scan_timer = core.callDelayed(interval_seconds_arg, _recurring_scanner_loop_task, interval_seconds_arg)
    log.info(f"[SCHEDULER] First recurring external scan scheduled in {interval_seconds_arg}s.")

def handle_connection_up(event):
    global _network_fully_up, _scan_timer
    log.info(f"[POX_EVENT] Switch {dpid_to_str(event.dpid)} connected.")
    if not _network_fully_up:
        _network_fully_up = True
        log.info(f"[SCHEDULER] Network up. Scheduling first external scan in {_initial_scan_delay_seconds}s (interval: {_scan_interval_seconds}s).")
        if _scan_timer: _scan_timer.cancel()
        _scan_timer = core.callDelayed(_initial_scan_delay_seconds, _initial_scanner_task, _scan_interval_seconds)

def launch(debug_mode=False): 
    global dos_cleanup_timer
    if str_to_bool(debug_mode): 
        log.setLevel("DEBUG")
        log.info("[POX_LAUNCH] Debug mode enabled by launch argument.")
    else:
        log.setLevel("INFO") 

    log.info("[POX_LAUNCH] IoT Sentinel POX Component Launching...")
    if not os.path.exists(acl_manager.file_path): 
        log.error(f"[POX_LAUNCH_CRITICAL] ACL config file missing: {acl_manager.file_path}.")
    
    core.openflow.addListenerByName("ConnectionUp", handle_connection_up)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn, priority=1) 
    
    dos_cleanup_timer = core.callDelayed(DOS_CLEANUP_INTERVAL, _cleanup_dos_trackers)
    log.info("[POX_LAUNCH] IoT Sentinel Component Loaded. DoS monitoring active. Waiting for switch for external scanning.")
