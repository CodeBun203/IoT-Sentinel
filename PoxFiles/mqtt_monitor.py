# /home/mininet/pox/pox/misc/mqtt_monitor.py

import sys
import os
import subprocess
import threading
import json
import time # For scan cycle timing

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.util import dpid_to_str

# --- Path Setup ---
try:
    pox_base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
    iot_sentinel_controllers_path = os.path.join(pox_base_dir, "IoTSentinel/controllers")
    iot_sentinel_scanners_path = os.path.join(pox_base_dir, "IoTSentinel/scanners")
    iot_sentinel_fixers_path = os.path.join(pox_base_dir, "IoTSentinel/fixers")

    for p in [iot_sentinel_controllers_path, iot_sentinel_fixers_path]:
        if p not in sys.path:
            sys.path.append(p)
    # print(f"[mqtt_monitor INFO] sys.path configured.") # Quieter startup
except Exception as e:
    print(f"[mqtt_monitor CRITICAL] Error setting up sys.path: {e}", file=sys.stderr)
    raise

# --- Module Imports ---
try:
    from acl import ACLManager
    from fwd_table import ForwardingTableManager
    from email_notifier import send_consolidated_email_notification, format_consolidated_vulnerabilities_for_email
    # print("[mqtt_monitor INFO] Successfully imported IoTSentinel modules & Email Notifier.") # Quieter
except ModuleNotFoundError as e:
    print(f"[mqtt_monitor CRITICAL] Failed to import IoTSentinel modules. Error: {e}", file=sys.stderr)
    if 'send_consolidated_email_notification' not in globals():
        def send_consolidated_email_notification(subject_prefix, body):
            print(f"[DUMMY_EMAIL_ALERT] Email Notifier not loaded. Subject Prefix: {subject_prefix}\nBody:\n{body}", file=sys.stderr)
            return False
        def format_consolidated_vulnerabilities_for_email(vulnerabilities_with_actions):
            subject_prefix = "[INFO] (Email N/A)"
            body = f"Scan Data (Email N/A): {vulnerabilities_with_actions}"
            return subject_prefix, body
        print("[mqtt_monitor WARNING] Email notifier functions could not be imported. Using dummies.", file=sys.stderr)
    if "ACLManager" not in globals() or "ForwardingTableManager" not in globals():
        raise
except ImportError as e: 
    print(f"[mqtt_monitor WARNING] ImportError for Email Notifier: {e}. Using dummies.", file=sys.stderr)
    if 'send_consolidated_email_notification' not in globals():
        def send_consolidated_email_notification(subject_prefix, body): # Define dummy if not defined
             print(f"[DUMMY_EMAIL_ALERT] Email Notifier not loaded. Subject Prefix: {subject_prefix}\nBody:\n{body}", file=sys.stderr)
             return False
        def format_consolidated_vulnerabilities_for_email(vulnerabilities_with_actions): # Define dummy
            subject_prefix = "[INFO] (Email N/A)"
            body = f"Scan Data (Email N/A): {vulnerabilities_with_actions}"
            return subject_prefix, body

log = core.getLogger() # POX's logger

acl_manager = ACLManager()
fwd_table_manager = ForwardingTableManager()

_network_fully_up = False
_scan_timer = None
_initial_scan_delay_seconds = 15
_scan_interval_seconds = 60 # Scan every 1 minute

_current_scan_cycle_results = []
_scanner_threads_expected = 0 # Number of scanners dispatched in current cycle
_scanner_threads_completed = 0 # Number of scanners completed in current cycle
_scan_cycle_lock = threading.Lock()
_scan_cycle_in_progress = False # Flag to prevent overlapping finalizations

def finalize_scan_cycle_reporting():
    global _current_scan_cycle_results, _scan_cycle_in_progress
    
    with _scan_cycle_lock:
        if not _scan_cycle_in_progress: # Should have been true to enter here from run_scanners
            log.warning("[SCAN_CYCLE_END] Finalize called but cycle not marked as in progress. This might be an issue.")
            # return # Or proceed cautiously
        
        # This function is now called only once after all expected scanners have finished.
        log.info(f"[SCAN_CYCLE_END] Finalizing report. Found {len(_current_scan_cycle_results)} items (vulns/fix attempts).")
        
        if not _current_scan_cycle_results:
            log.info("[SCAN_CYCLE_END] No vulnerabilities or action items to report in this cycle.")
            subject_prefix, email_body = format_consolidated_vulnerabilities_for_email([])
        else:
            subject_prefix, email_body = format_consolidated_vulnerabilities_for_email(_current_scan_cycle_results)
        
        send_consolidated_email_notification(subject_prefix, email_body)
        
        _current_scan_cycle_results = [] # Clear for next cycle
        _scan_cycle_in_progress = False # Mark cycle as completed
        log.debug("[SCAN_CYCLE_END] Scan results cleared and cycle marked as not in progress.")

def _scanner_thread_completed_callback():
    """Called by each scanner thread upon completion."""
    global _scanner_threads_completed, _scanner_threads_expected
    with _scan_cycle_lock:
        _scanner_threads_completed += 1
        log.debug(f"[SCANNER_THREAD_COMPLETED_CB] A scanner thread finished. Completed: {_scanner_threads_completed}/{_scanner_threads_expected}")
        if _scanner_threads_completed >= _scanner_threads_expected and _scan_cycle_in_progress:
            log.info(f"[SCAN_CYCLE] All {_scanner_threads_expected} scanner threads for this cycle have reported completion.")
            # It's now safe to finalize the report.
            # Using callLater to ensure this runs in the main POX thread.
            core.callLater(finalize_scan_cycle_reporting)
        elif _scanner_threads_completed > _scanner_threads_expected:
            log.warning(f"[SCANNER_THREAD_COMPLETED_CB] Completed count ({_scanner_threads_completed}) exceeded expected ({_scanner_threads_expected}). Resetting counters.")
            # This case might indicate a logic flaw or rapid restarts.
            # For safety, call finalize if a cycle was thought to be in progress.
            if _scan_cycle_in_progress:
                core.callLater(finalize_scan_cycle_reporting)
            else: # Reset if no cycle was active.
                _scanner_threads_completed = 0
                _scanner_threads_expected = 0


def _execute_scanner_threaded(scanner_name, command):
    log.info(f"[SCANNER_THREAD] Starting: {scanner_name}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=180)
        if result.stdout and result.stdout.strip():
            log.debug(f"[SCANNER_THREAD_STDOUT] {scanner_name}:\n{result.stdout.strip()}")
            core.callLater(process_scanner_output, scanner_name, result.stdout.strip())
        else:
            log.warning(f"[SCANNER_THREAD] {scanner_name} produced NO STDOUT.")
        if result.stderr and result.stderr.strip():
            log.info(f"[SCANNER_THREAD_STDERR] {scanner_name}:\n{result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        log.error(f"[SCANNER_THREAD_TIMEOUT] {scanner_name} timed out.")
        # Still record that this scanner "attempted" and "timed out" for consolidated report
        with _scan_cycle_lock:
            _current_scan_cycle_results.append(
                ({"scanner": scanner_name, "vulnerability": "scanner_timeout", "ip": "N/A", "details": f"{scanner_name} timed out.", "severity":"ERROR"}, 
                 f"Execution of {scanner_name}", 
                 "Timed out")
            )
    except Exception as e: # Catch other exceptions like FileNotFoundError
        log.error(f"[SCANNER_THREAD_EXCEPTION] Error running {scanner_name}: {e}", exc_info=True)
        with _scan_cycle_lock:
            _current_scan_cycle_results.append(
                ({"scanner": scanner_name, "vulnerability": "scanner_error", "ip": "N/A", "details": f"Error running {scanner_name}: {e}", "severity":"ERROR"}, 
                 f"Execution of {scanner_name}", 
                 f"Failed with exception: {e}")
            )
    finally:
        # This callback will check if all scanners are done and trigger finalization
        core.callLater(_scanner_thread_completed_callback)


def run_scanners():
    global _scanner_threads_expected, _scanner_threads_completed, _current_scan_cycle_results, _scan_cycle_in_progress
    
    with _scan_cycle_lock:
        if _scan_cycle_in_progress:
            log.warning("[SCANNER_DISPATCH] Scan cycle initiated while previous one might still be finalizing. This could lead to issues.")
            # Depending on desired behavior, you might skip this new cycle or queue it.
            # For now, we'll let it proceed but it might interleave with finalize_scan_cycle_reporting.
            # A better approach might be to ensure finalize_scan_cycle_reporting truly blocks a new cycle.
        
        log.info("[SCANNER_DISPATCH] Starting new scan cycle.")
        _current_scan_cycle_results = [] # Reset results for the new cycle
        _scanner_threads_expected = 0
        _scanner_threads_completed = 0
        _scan_cycle_in_progress = True # Mark that a cycle has started

    scanners_to_run = {
        "iot_port_scanner": ["python3", os.path.join(iot_sentinel_scanners_path, "iot_scanner.py")],
        "ssh_scanner": ["python3", os.path.join(iot_sentinel_scanners_path, "ssh_scanner.py")]
    }

    if not scanners_to_run:
        log.info("[SCANNER_DISPATCH] No scanners configured.")
        with _scan_cycle_lock: # Ensure state is consistent
            _scan_cycle_in_progress = False # No scanners, so cycle effectively ends
        core.callLater(finalize_scan_cycle_reporting) # Send empty report
        return

    _scanner_threads_expected = len(scanners_to_run)
    log.debug(f"[SCANNER_DISPATCH] Expecting {_scanner_threads_expected} scanner threads for this cycle.")

    for scanner_name, command in scanners_to_run.items():
        thread = threading.Thread(target=_execute_scanner_threaded, args=(scanner_name, command), daemon=True)
        thread.start()
        log.debug(f"[SCANNER_DISPATCH] Thread launched for {scanner_name}")
    
    # If, for some reason, len(scanners_to_run) was 0 after all.
    if _scanner_threads_expected == 0:
        log.info("[SCANNER_DISPATCH] No scanner threads were actually launched in this cycle (e.g. empty config).")
        with _scan_cycle_lock:
             _scan_cycle_in_progress = False # Mark cycle as ended.
        core.callLater(finalize_scan_cycle_reporting)


def _execute_fixer_threaded(fixer_name, command_args, original_scan_result_data):
    global _current_scan_cycle_results
    full_command = ["python3", os.path.join(iot_sentinel_fixers_path, fixer_name + ".py")] + command_args
    log.info(f"[FIXER_THREAD] Starting: {fixer_name} for IP {original_scan_result_data.get('ip')}")
    
    action_description = f"Ran fixer '{fixer_name}' for IP '{original_scan_result_data.get('ip', 'N/A')}'"
    if "username" in original_scan_result_data:
        action_description += f" user '{original_scan_result_data['username']}'"
    
    outcome_message = "Fixer script execution resulted in an unknown state."
    fix_successful = False # Default

    try:
        result = subprocess.run(full_command, capture_output=True, text=True, check=False, timeout=180)
        log.debug(f"[FIXER_THREAD_RAW_RESULT] {fixer_name} (IP: {original_scan_result_data.get('ip')}) - RC: {result.returncode}")

        if result.stdout and result.stdout.strip():
            log.debug(f"[FIXER_THREAD_STDOUT] {fixer_name}:\n{result.stdout.strip()}")
            try:
                parsed_fixer_json = json.loads(result.stdout.strip())
                fix_successful = parsed_fixer_json.get("success", False)
                outcome_message = parsed_fixer_json.get("message", "Fixer provided no detailed message.")
            except json.JSONDecodeError:
                log.error(f"[FIXER_THREAD_ERROR] Could not parse JSON from {fixer_name}: {result.stdout.strip()}")
                outcome_message = "Fixer script output was not valid JSON."
        else:
            log.warning(f"[FIXER_THREAD] {fixer_name} produced NO STDOUT.")
            outcome_message = "Fixer script produced no standard output."

        if result.stderr and result.stderr.strip():
            log.info(f"[FIXER_THREAD_STDERR] {fixer_name}:\n{result.stderr.strip()}")
            if not (result.stdout and result.stdout.strip()):
                 outcome_message += f" (Stderr: {result.stderr.strip()})"
        
        log_level = log.info if fix_successful else log.warning
        log_level(f"[FIXER_OUTCOME] Fixer '{fixer_name}' for IP '{original_scan_result_data.get('ip', 'N/A')}' reported: Success={fix_successful}, Message='{outcome_message}'")

    except subprocess.TimeoutExpired:
        log.error(f"[FIXER_THREAD_TIMEOUT] {fixer_name} timed out.")
        outcome_message = "Fixer script timed out."
    except FileNotFoundError:
        log.error(f"[FIXER_THREAD_ERROR] Script not found for {fixer_name}: {full_command[1]}")
        outcome_message = f"Fixer script '{fixer_name}.py' not found."
    except Exception as e:
        log.error(f"[FIXER_THREAD_EXCEPTION] Error running {fixer_name}: {e}", exc_info=True)
        outcome_message = f"Exception running fixer: {str(e)}"
    
    with _scan_cycle_lock:
        _current_scan_cycle_results.append(
            (original_scan_result_data, action_description, outcome_message)
        )

def orchestrate_fixer(scan_result_data):
    global _current_scan_cycle_results
    vuln_type = scan_result_data.get("vulnerability")
    ip = scan_result_data.get("ip")

    if not vuln_type or not ip:
        log.warning("[FIXER_ORCHESTRATOR] Vuln type or IP missing. Cannot orchestrate fix.")
        with _scan_cycle_lock:
            _current_scan_cycle_results.append(
                (scan_result_data, "Fixer Orchestration Skipped", "Incomplete scan data (missing type or IP).")
            )
        return

    log.info(f"[FIXER_ORCHESTRATOR] Vulnerability: '{vuln_type}' on {ip}. Deciding on fixer.")

    fixer_name = None
    fixer_args = []
    
    action_desc_if_no_fixer = f"Identified '{vuln_type}' on {ip}."
    outcome_if_no_fixer = "No specific automated fixer action taken/configured for this type."


    if vuln_type == "weak_ssh_credentials":
        username = scan_result_data.get("username")
        old_password = scan_result_data.get("found_password") 
        if username and old_password and old_password != "****":
            fixer_name = "ssh_fixer"
            fixer_args = [ip, username, old_password]
        else:
            log.warning(f"[FIXER_ORCHESTRATOR] Username or actual old_password missing for weak_ssh_credentials on {ip}. Cannot run ssh_fixer.")
            with _scan_cycle_lock:
                _current_scan_cycle_results.append(
                    (scan_result_data, f"Fix attempt for weak SSH on {ip} (user {username})", "Failed: Missing username or actual old password from scan data.")
                )
            return

    elif vuln_type == "open_telnet_port" or \
         (vuln_type == "open_ports" and 23 in scan_result_data.get("ports",[])):
        log.info(f"[FIXER_ORCHESTRATOR] Detected open Telnet on {ip}. No automated Telnet fixer implemented.")
        with _scan_cycle_lock:
             _current_scan_cycle_results.append(
                (scan_result_data, action_desc_if_no_fixer.replace("'{vuln_type}'", "open Telnet port"), "No automated Telnet fixer. Manual investigation advised.")
            )
        return 
            
    elif vuln_type == "open_ports" and 80 in scan_result_data.get("ports", []) and ip != "10.0.0.100":
        log.info(f"[FIXER_ORCHESTRATOR] Detected open HTTP on {ip}. No automated HTTP fixer implemented.")
        with _scan_cycle_lock:
            _current_scan_cycle_results.append(
                (scan_result_data, action_desc_if_no_fixer.replace("'{vuln_type}'", "open HTTP port"), "No automated HTTP port fixer. Manual investigation advised.")
            )
        return
    
    elif vuln_type == "open_ports": # Generic open_ports not covered above
        ports = scan_result_data.get("ports", [])
        log.info(f"[FIXER_ORCHESTRATOR] Open port(s) {ports} on {ip} detected, no specific fixer logic here.")
        with _scan_cycle_lock:
            _current_scan_cycle_results.append(
                (scan_result_data, action_desc_if_no_fixer.replace("'{vuln_type}'", f"open port(s) {ports}"), outcome_if_no_fixer)
            )
        return
    else: 
        log.info(f"[FIXER_ORCHESTRATOR] No fixer defined for vulnerability type: '{vuln_type}' on {ip}.")
        with _scan_cycle_lock:
            _current_scan_cycle_results.append(
                 (scan_result_data, action_desc_if_no_fixer, outcome_if_no_fixer)
            )
        return

    if fixer_name:
        log.info(f"[FIXER_ORCHESTRATOR] Dispatching fixer '{fixer_name}' for IP '{ip}' with args: {fixer_args}")
        thread = threading.Thread(target=_execute_fixer_threaded, args=(fixer_name, fixer_args, scan_result_data), daemon=True)
        thread.start()
    # If no fixer_name was set, the item was already added to _current_scan_cycle_results by the elif blocks.

def process_scanner_output(scanner_name, output_str):
    log.info(f"[PROCESS_SCANNER] Processing output from {scanner_name}...")
    lines = output_str.strip().split('\n')
    if not lines or not output_str.strip():
        log.warning(f"[PROCESS_SCANNER] No content from {scanner_name}.")
        return

    for line_num, line in enumerate(lines):
        line = line.strip()
        if not line: continue
        try:
            data = json.loads(line)
            if data.get("status"):
                log.info(f"[SCANNER_STATUS] {scanner_name}: {data.get('status')} (Targets: {data.get('targets_checked', 'N/A')})")
                # Also add status messages to the report for completeness if desired
                with _scan_cycle_lock:
                    _current_scan_cycle_results.append(
                        (data, f"Status update from {scanner_name}", data.get('status'))
                    )
                continue 
            
            log.warning(f"[VULN_DETECTED] Source: {scanner_name}, Type: {data.get('vulnerability','N/A')}, IP: {data.get('ip','N/A')}, Severity: {str(data.get('severity','N/A')).upper()}")
            orchestrate_fixer(data)
            
        except json.JSONDecodeError:
            log.error(f"[PROCESS_SCANNER_PARSE_ERROR] JSONDecodeError from {scanner_name}: '{line}'")
        except Exception as e:
            log.error(f"[PROCESS_SCANNER_ERROR] Exception from {scanner_name}: {e} - Data: '{line}'", exc_info=True)

def _handle_PacketIn(event):
    packet = event.parsed
    if not packet.parsed: return

    ip_packet = packet.find(ipv4)
    if not ip_packet: return

    # Default to less verbose, only log "interesting" packets at INFO
    is_interesting = False
    dst_port_for_acl = 0
    tcp_packet = packet.find(tcp)

    if tcp_packet:
        dst_port_for_acl = tcp_packet.dstport
        if dst_port_for_acl in [22, 23, 80, 1883] or tcp_packet.srcport in [22, 23, 80, 1883]:
            is_interesting = True
            log.info(f"[PACKET_IN] TCP: {ip_packet.srcip}:{tcp_packet.srcport} -> {ip_packet.dstip}:{dst_port_for_acl}")
    elif ip_packet.protocol == 1: # ICMP
        is_interesting = True
        log.info(f"[PACKET_IN] ICMP: {ip_packet.srcip} -> {ip_packet.dstip}")
    elif ip_packet.protocol == 17 and (ip_packet.dstip.toStr().startswith("224.") or ip_packet.dstip.toStr().startswith("ff0")): # UDP Multicast (e.g. mDNS)
        is_interesting = False # Usually too noisy for INFO
        log.debug(f"[PACKET_IN_ROUTINE] UDP Multicast: {ip_packet.srcip} -> {ip_packet.dstip}")
    
    if not is_interesting:
        log.debug(f"[PACKET_IN_ROUTINE] Other: {ip_packet.srcip} -> {ip_packet.dstip} (Proto: {ip_packet.protocol})")


    if acl_manager.check_acl(str(ip_packet.dstip), dst_port_for_acl, ip_packet.protocol):
        if is_interesting : log.info(f"[ACL_PASS] {ip_packet.srcip} -> {ip_packet.dstip} (Port:{dst_port_for_acl}, Proto:{ip_packet.protocol})")
        
        forwarding_entry = fwd_table_manager.get_next_hop(str(ip_packet.dstip))
        out_port = forwarding_entry.get("port") if forwarding_entry else None
        
        if out_port is not None:
            match = of.ofp_match.from_packet(packet, event.port)
            msg = of.ofp_flow_mod(match=match, idle_timeout=10, hard_timeout=30)
            msg.actions.append(of.ofp_action_output(port=out_port))
            if event.ofp and event.ofp.buffer_id != -1: msg.buffer_id = event.ofp.buffer_id
            else: msg.data = event.ofp
            event.connection.send(msg)
            if is_interesting: log.debug(f"[FLOW_MOD] FWD_TABLE: ALLOWED {ip_packet.srcip} -> {ip_packet.dstip} to port {out_port}")
            return 
        else: # No static rule, ACL passed, let l2_learning handle
            if is_interesting: log.debug(f"[FORWARDING] No static fwd rule for {ip_packet.dstip}. ACL passed. Propagating.")
    else: # ACL Blocked
        log.warning(f"[ACL_BLOCK] TRAFFIC BLOCKED by ACL: {ip_packet.srcip} -> {ip_packet.dstip} (Port:{dst_port_for_acl}, Proto:{ip_packet.protocol})")
        msg = of.ofp_flow_mod(match=of.ofp_match.from_packet(packet, event.port), idle_timeout=60, hard_timeout=120)
        event.connection.send(msg)
        if is_interesting: log.debug(f"[FLOW_MOD] EXPLICIT DROP for ACL_BLOCK: {ip_packet.srcip} -> {ip_packet.dstip}")
        return 

# --- Scheduler functions ---
def _recurring_scanner_loop_task(interval_seconds_arg):
    global _scan_timer, _scan_cycle_in_progress
    with _scan_cycle_lock: # Ensure we don't start a new scan if one is somehow still finalizing
        if _scan_cycle_in_progress:
            log.warning("[SCHEDULER_LOOP_RECURRING] Previous scan cycle finalization may not have completed. Skipping this scheduled scan to avoid overlap.")
            _scan_timer = core.callDelayed(interval_seconds_arg, _recurring_scanner_loop_task, interval_seconds_arg) # Reschedule
            return

    if _network_fully_up:
        run_scanners() # This sets _scan_cycle_in_progress = True
    else:
        log.info("[SCHEDULER_LOOP_RECURRING] Network not up, skipping scan cycle.")
    _scan_timer = core.callDelayed(interval_seconds_arg, _recurring_scanner_loop_task, interval_seconds_arg)
    log.info(f"[SCHEDULER] Next full scan cycle scheduled in {interval_seconds_arg}s.")

def _initial_scanner_task(interval_seconds_arg):
    global _scan_timer
    if _network_fully_up:
        run_scanners() # This sets _scan_cycle_in_progress = True
    else:
        log.info("[SCHEDULER_LOOP_INIT] Network not up, skipping first scan cycle.")
    _scan_timer = core.callDelayed(interval_seconds_arg, _recurring_scanner_loop_task, interval_seconds_arg)
    log.info(f"[SCHEDULER] First recurring scan scheduled in {interval_seconds_arg}s.")

def handle_connection_up(event):
    global _network_fully_up, _scan_timer
    log.info(f"[POX_EVENT] Switch {dpid_to_str(event.dpid)} connected.")
    if not _network_fully_up:
        _network_fully_up = True
        log.info(f"[SCHEDULER] Network up. Scheduling first scan in {_initial_scan_delay_seconds}s (interval: {_scan_interval_seconds}s).")
        if _scan_timer: _scan_timer.cancel()
        _scan_timer = core.callDelayed(_initial_scan_delay_seconds, _initial_scanner_task, _scan_interval_seconds)

def launch():
    # To make POX's own components less verbose if needed:
    # core.getLogger("openflow.of_01").setLevel("WARNING")
    # core.getLogger("forwarding.l2_learning").setLevel("WARNING") 
    
    # Configure our module's logger. Can be overridden by command line.
    # log.setLevel("INFO") # Default to INFO if not set by command line

    log.info("[POX_LAUNCH] IoT Sentinel POX Component Launching...")
    # acl_manager is initialized globally now, this check is for the file itself
    if not os.path.exists(acl_manager.file_path): 
        log.error(f"[POX_LAUNCH_CRITICAL] ACL config file missing: {acl_manager.file_path}.")
    
    core.openflow.addListenerByName("ConnectionUp", handle_connection_up)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn, priority=1) 
    
    log.info("[POX_LAUNCH] IoT Sentinel Component Loaded. Waiting for switch to initialize scanning.")
