# /home/mininet/pox/pox/misc/mqtt_monitor.py
import sys
import os
import subprocess
import threading
import json
import time
from datetime import datetime # For timestamps

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from pox.lib.packet.icmp import icmp
from pox.lib.addresses import IPAddr, EthAddr # Ensure EthAddr is imported if used for MACs
from pox.lib.util import dpid_to_str, str_to_bool

# --- Path Setup ---
try:
    # Assuming this POX module is in pox/pox/misc/
    pox_base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
    iot_sentinel_base_path = os.path.join(pox_base_dir, "IoTSentinel") # No trailing slash needed here
    iot_sentinel_controllers_path = os.path.join(iot_sentinel_base_path, "controllers")
    iot_sentinel_scanners_path = os.path.join(iot_sentinel_base_path, "scanners")
    iot_sentinel_fixers_path = os.path.join(iot_sentinel_base_path, "fixers")

    # Define paths for UI communication files
    LATEST_EVENTS_PATH = os.path.join(iot_sentinel_base_path, "logs/latest_events.json")
    MASTER_LOG_PATH = os.path.join(iot_sentinel_base_path, "logs/master_event_log.json")
    COMMAND_QUEUE_PATH = os.path.join(iot_sentinel_base_path, "logs/command_queue.json")
    NETWORK_TOPOLOGY_PATH = os.path.join(iot_sentinel_base_path, "logs/network_topology.json")
    DEVICE_NAMES_PATH = os.path.join(iot_sentinel_base_path, "config/device_names.json")

    # Add project subdirectories to Python's import path
    for p_path in [iot_sentinel_controllers_path, iot_sentinel_fixers_path, iot_sentinel_scanners_path]:
        if p_path not in sys.path:
            sys.path.append(p_path)
except Exception as e:
    # Use print for critical startup errors as logger might not be ready
    print(f"[mqtt_monitor CRITICAL] Error setting up sys.path: {e}", file=sys.stderr)
    raise # Stop execution if paths can't be set

# --- Module Imports for IoTSentinel specific components ---
try:
    from acl import ACLManager
    # email_notifier functions are used in finalize_scan_cycle_reporting
    from email_notifier import send_consolidated_email_notification, format_consolidated_vulnerabilities_for_email
except ModuleNotFoundError as e:
    print(f"[mqtt_monitor CRITICAL] Failed to import IoTSentinel modules (ACLManager or email_notifier). Error: {e}", file=sys.stderr)
    # Define dummy functions if email_notifier fails, as ACLManager is critical
    if 'send_consolidated_email_notification' not in globals():
        def send_consolidated_email_notification(subject_prefix, body):
            print(f"[DUMMY_EMAIL_ALERT] Email Notifier not loaded. Subject: {subject_prefix}\nBody:\n{body}", file=sys.stderr)
            return False
        def format_consolidated_vulnerabilities_for_email(vulnerabilities_with_actions):
            return "[INFO] (Email N/A)", f"Scan Data (Email N/A): {vulnerabilities_with_actions}"
        print("[mqtt_monitor WARNING] Email notifier functions could not be imported. Using dummies.", file=sys.stderr)
    if "ACLManager" not in globals(): # ACLManager is critical for operation
        raise # Re-raise if ACLManager cannot be imported
except ImportError as e: # Catch other import errors specifically
    print(f"[mqtt_monitor WARNING] ImportError for some IoTSentinel modules: {e}. Using dummies where applicable.", file=sys.stderr)
    if 'send_consolidated_email_notification' not in globals():
        def send_consolidated_email_notification(subject_prefix, body):
             print(f"[DUMMY_EMAIL_ALERT] Email Notifier not loaded. Subject: {subject_prefix}\nBody:\n{body}", file=sys.stderr)
             return False
        def format_consolidated_vulnerabilities_for_email(vulnerabilities_with_actions):
            return "[INFO] (Email N/A)", f"Scan Data (Email N/A): {vulnerabilities_with_actions}"

# POX core logger
log = core.getLogger()

# --- Global Variables ---
# Will be initialized in launch()
acl_manager = None
device_names_map = {} # For storing names loaded from device_names.json

# For L2 learning switch functionality
mac_to_port_table = {}  # Structure: {dpid: {mac_addr_EthAddr: port_num}}
active_switches = {}    # Structure: {dpid_int: pox_connection_object}
mac_to_ip_table = {}    # Structure: {mac_addr_EthAddr: ip_addr_IPAddr}

# --- Central Configuration Loading ---
config = {} # Initialize as empty dictionary
try:
    config_path = os.path.join(iot_sentinel_base_path, "config/sentinel_config.json")
    with open(config_path, 'r') as f:
        config = json.load(f)
    log.info(f"Successfully loaded configuration from {config_path}")
except Exception as e:
    log.critical(f"Could not load sentinel_config.json from {config_path}: {e}. Using default values for safety.")
    # Define defaults for essential config structures if file fails to load
    config = {
        "scanning": {"initial_delay_seconds": 30, "interval_seconds": 300, "scanners_to_run": []},
        "dos_detection": {"window_seconds": 10, "syn_flood_threshold": 50, "udp_flood_threshold": 500, 
                          "icmp_flood_threshold": 100, "dos_alert_cooldown_seconds": 120, 
                          "dos_cleanup_interval": 20, "dos_logic_budget_per_ip": 1000, 
                          "dos_logic_budget_window_seconds": 1.0, "packet_in_log_interval": 5.0},
        # Add other sections like "notifications" with defaults if needed
    }

# --- Assign to Global Variables from Loaded Config ---
# Scanning parameters
scanning_config = config.get("scanning", {})
_initial_scan_delay_seconds = scanning_config.get("initial_delay_seconds", 15)
_scan_interval_seconds = scanning_config.get("interval_seconds", 120)
_scanners_to_run_names = scanning_config.get("scanners_to_run", [])

# DoS detection parameters
dos_settings = config.get("dos_detection", {})
DOS_WINDOW_SECONDS = dos_settings.get("window_seconds", 10)
SYN_FLOOD_THRESHOLD = dos_settings.get("syn_flood_threshold", 20)
CONNECTION_RATE_THRESHOLD = dos_settings.get("connection_rate_threshold", 100) # If you re-add connection rate logic
UDP_PACKET_RATE_THRESHOLD = dos_settings.get("udp_flood_threshold", 200)
ICMP_PACKET_RATE_THRESHOLD = dos_settings.get("icmp_flood_threshold", 50)
DOS_ALERT_COOLDOWN_SECONDS = dos_settings.get("dos_alert_cooldown_seconds", 120)
DOS_CLEANUP_INTERVAL = dos_settings.get("dos_cleanup_interval", DOS_WINDOW_SECONDS * 2)
DOS_LOGIC_BUDGET_PER_IP = dos_settings.get("dos_logic_budget_per_ip", 1000)
DOS_LOGIC_BUDGET_WINDOW_SECONDS = dos_settings.get("dos_logic_budget_window_seconds", 1.0)

# --- System State Globals ---
_network_fully_up = False
_scan_timer = None
_topology_save_timer = None # For periodically saving network topology

# Results and synchronization for scan/fix cycles
_current_scan_cycle_results = [] # Stores tuples: (scan_data_dict, action_desc_str, outcome_msg_str)
_scan_cycle_lock = threading.Lock() # To protect shared access to results and counters
_scan_cycle_active = False # True if an external scanner cycle is running
_external_scanners_dispatched = 0
_external_scanners_completed = 0
_fixers_dispatched_this_cycle = 0
_fixers_completed_this_cycle = 0

# DoS Tracking Dictionaries (initialized empty)
syn_packet_volume_tracker = {}
connection_tracker = {} # If you re-add specific connection rate logic
udp_flood_tracker = {}
icmp_flood_tracker = {}
dos_alert_cooldown = {} # Stores cooldown timestamps for (vuln_type, target_ip, target_port)
dos_state_lock = threading.Lock() # Lock specifically for DoS tracker dictionaries
dos_cleanup_timer = None

# For DoS logic rate limiting and PacketIn statistics
_dos_logic_budget_tracker = {} 
_packet_in_stats = { 
    "count_since_last_log": 0,
    "last_log_time": time.time(),
    "log_interval_seconds": dos_settings.get("packet_in_log_interval", 5.0)
}

# --- Helper Functions for DoS ---
def _is_on_cooldown(vuln_type, target_ip_str, target_port=None):
    key = (vuln_type, target_ip_str, target_port)
    last_alert_time = dos_alert_cooldown.get(key)
    if last_alert_time and (time.time() - last_alert_time) < DOS_ALERT_COOLDOWN_SECONDS:
        return True
    return False

def _set_cooldown(vuln_type, target_ip_str, target_port=None):
    key = (vuln_type, target_ip_str, target_port)
    dos_alert_cooldown[key] = time.time()

def _cleanup_dos_trackers():
    global syn_packet_volume_tracker, connection_tracker, udp_flood_tracker, icmp_flood_tracker, dos_alert_cooldown, dos_cleanup_timer
    current_time = time.time()
    cleaned_count = 0
    with dos_state_lock:
        keys_to_del = [k for k, ts in list(dos_alert_cooldown.items()) if current_time - ts > DOS_ALERT_COOLDOWN_SECONDS * 1.5]
        for key in keys_to_del:
            if key in dos_alert_cooldown: del dos_alert_cooldown[key]; cleaned_count+=1
        keys_to_del = [k for k, data in list(syn_packet_volume_tracker.items()) if current_time - data.get("window_start_time", 0) > DOS_WINDOW_SECONDS * 1.5]
        for key in keys_to_del:
            if key in syn_packet_volume_tracker: del syn_packet_volume_tracker[key]; cleaned_count+=1
        for dst_ip, sources in list(connection_tracker.items()): # If connection_tracker is used
            active = {src: ts for src, ts in sources.items() if current_time - ts <= DOS_WINDOW_SECONDS * 1.5}
            if not active:
                if dst_ip in connection_tracker: del connection_tracker[dst_ip]; cleaned_count+=1
            else: connection_tracker[dst_ip] = active
        keys_to_del = [k for k, data in list(udp_flood_tracker.items()) if current_time - data.get("window_start_time", 0) > DOS_WINDOW_SECONDS * 1.5]
        for key in keys_to_del:
            if key in udp_flood_tracker: del udp_flood_tracker[key]; cleaned_count+=1
        keys_to_del = [k for k, data in list(icmp_flood_tracker.items()) if current_time - data.get("window_start_time", 0) > DOS_WINDOW_SECONDS * 1.5]
        for key in keys_to_del:
            if key in icmp_flood_tracker: del icmp_flood_tracker[key]; cleaned_count+=1
    if cleaned_count > 0:
        log.debug(f"[DOS_TRACKER_CLEANUP] Cleaned {cleaned_count} stale entries.")
    if core.running:
        dos_cleanup_timer = core.callDelayed(DOS_CLEANUP_INTERVAL, _cleanup_dos_trackers)

# --- Core Logic: Topology, Reporting, Scanners, Fixers ---
def save_network_topology():
    global device_names_map, active_switches, mac_to_port_table, mac_to_ip_table
    topology_data = {"nodes": [], "links": []}
    controller_node_id = "pox_controller_node"
    added_node_ids = set()

    controller_raw_label = "🧠 SDN Controller (POX)"
    controller_display_label = device_names_map.get("by_id", {}).get(controller_node_id, "Controller")
    topology_data["nodes"].append({"id": controller_node_id,
                                   "type": "controller", 
                                   "data": {"label": controller_display_label, "raw_label": controller_raw_label}
                                  })
    added_node_ids.add(controller_node_id)

    current_active_switches = list(active_switches.keys())
    for dpid in current_active_switches:
        dpid_str = dpid_to_str(dpid)
        switch_raw_label = f"⇄ Switch\nDPID: {dpid_str}"
        switch_display_label = device_names_map.get("by_id", {}).get(dpid_str, "Switch")
        if dpid_str not in added_node_ids:
            topology_data["nodes"].append({"id": dpid_str,
                                           "type": "switch",
                                           "data": {"label": switch_display_label, "raw_label": switch_raw_label}
                                          })
            added_node_ids.add(dpid_str)
        topology_data["links"].append({"id": f"link-s_{dpid_str}-c_{controller_node_id}",
                                       "source": dpid_str,
                                       "target": controller_node_id,
                                       "label": "Manages"
                                      })

    current_mac_to_port_table = dict(mac_to_port_table)
    for dpid, mac_mappings in current_mac_to_port_table.items():
        dpid_str = dpid_to_str(dpid)
        if dpid not in active_switches: continue

        for mac, port_num in mac_mappings.items():
            host_id_mac = str(mac)
            ip_addr = str(mac_to_ip_table.get(mac, "IP N/A"))
            display_name = device_names_map.get("by_mac", {}).get(host_id_mac.lower())
            if not display_name and ip_addr != "N/A":
                display_name = device_names_map.get("by_ip", {}).get(ip_addr)
            if not display_name: display_name = "Host"

            host_raw_label = f"💻 Host\nMAC: {host_id_mac}\nIP: {ip_addr}"
            if host_id_mac not in added_node_ids:
                 topology_data["nodes"].append({
                     "id": host_id_mac,
                     "type": "host",
                     "data": {"label": display_name, "raw_label": host_raw_label}
                 })
                 added_node_ids.add(host_id_mac)
            topology_data["links"].append({"id": f"link-h_{host_id_mac}-s_{dpid_str}_p{port_num}", 
                                           "source": host_id_mac,
                                           "target": dpid_str,
                                           "label": f"Port {port_num}"
                                          })
    try:
        logs_dir = os.path.join(iot_sentinel_base_path, "logs")
        if not os.path.exists(logs_dir): os.makedirs(logs_dir)
        with open(NETWORK_TOPOLOGY_PATH, 'w') as f:
            json.dump(topology_data, f, indent=4)
        log.debug(f"Network topology saved to {NETWORK_TOPOLOGY_PATH}")
    except Exception as e: log.error(f"Error saving network topology: {e}")

def _save_topology_periodically():
    global _topology_save_timer
    if core.running and _network_fully_up : 
        try: save_network_topology()
        except Exception as e: log.error(f"Error during periodic topology save: {e}")
    if core.running: 
        _topology_save_timer = core.callDelayed(15, _save_topology_periodically)

def finalize_scan_cycle_reporting():
    global _current_scan_cycle_results
    with _scan_cycle_lock:
        if not _current_scan_cycle_results:
            log.info("[FINALIZE_REPORT] No new events to report for this cycle.")
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        results_for_this_cycle_obj = {"timestamp": timestamp, "events": list(_current_scan_cycle_results)}
        log.info(f"[FINALIZE_REPORT] Generating report for {len(results_for_this_cycle_obj['events'])} events at {timestamp}.")
        _current_scan_cycle_results = [] 

    try:
        with open(LATEST_EVENTS_PATH, 'w') as f: json.dump(results_for_this_cycle_obj, f, indent=4)
        log.info(f"Wrote latest events to {LATEST_EVENTS_PATH} for Dashboard.")
    except IOError as e: log.error(f"[FINALIZE_REPORT] Could not write to latest events file: {e}")

    try:
        master_log_content = []
        if os.path.exists(MASTER_LOG_PATH):
            with open(MASTER_LOG_PATH, 'r') as f:
                try: master_log_content = json.load(f)
                except json.JSONDecodeError: master_log_content = []
            if not isinstance(master_log_content, list): master_log_content = []
        master_log_content.append(results_for_this_cycle_obj)
        with open(MASTER_LOG_PATH, 'w') as f: json.dump(master_log_content, f, indent=4)
        log.info(f"Appended current cycle's events to {MASTER_LOG_PATH} for Logs.")
    except IOError as e: log.error(f"[FINALIZE_REPORT] Could not write to master log file: {e}")

    if results_for_this_cycle_obj['events']:
        actual_vulnerability_events = [event_tuple for event_tuple in results_for_this_cycle_obj['events'] if event_tuple[0].get("vulnerability")]
        if actual_vulnerability_events:
            subject_prefix, email_body = format_consolidated_vulnerabilities_for_email(actual_vulnerability_events)
            send_consolidated_email_notification(subject_prefix, email_body)

def _check_if_scan_cycle_fully_complete():
    global _scan_cycle_active, _external_scanners_dispatched, _external_scanners_completed
    global _fixers_dispatched_this_cycle, _fixers_completed_this_cycle
    with _scan_cycle_lock:
        if not _scan_cycle_active:
            if _current_scan_cycle_results and (_fixers_completed_this_cycle >= _fixers_dispatched_this_cycle):
                log.info("[SYNC_CHECK] No active external scan, but internal results/fixers complete.")
                core.callLater(finalize_scan_cycle_reporting)
                _fixers_dispatched_this_cycle = 0; _fixers_completed_this_cycle = 0
            return
        scanners_done = (_external_scanners_completed >= _external_scanners_dispatched)
        fixers_done = (_fixers_completed_this_cycle >= _fixers_dispatched_this_cycle)
        log.debug(f"[SYNC_CHECK] Cycle Active. Scanners: {_external_scanners_completed}/{_external_scanners_dispatched}. Fixers: {_fixers_completed_this_cycle}/{_fixers_dispatched_this_cycle}.")
        if scanners_done and fixers_done:
            log.info("[SYNC_CHECK] Active scan cycle fully complete.")
            core.callLater(finalize_scan_cycle_reporting) 
            _scan_cycle_active = False 

def _external_scanner_completed_callback():
    global _external_scanners_completed 
    with _scan_cycle_lock: 
        _external_scanners_completed += 1
    _check_if_scan_cycle_fully_complete() 

def _fixer_thread_completed_callback(fixer_name="Unknown Fixer"): 
    global _fixers_completed_this_cycle 
    with _scan_cycle_lock: 
        _fixers_completed_this_cycle += 1
    _check_if_scan_cycle_fully_complete() 

def _execute_scanner_threaded(scanner_name, command):
    global _current_scan_cycle_results 
    log.info(f"[SCANNER_THREAD] Starting: {scanner_name} with command: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=180)
        if result.stdout and result.stdout.strip():
            log.debug(f"[SCANNER_THREAD_STDOUT] {scanner_name}:\n{result.stdout.strip()}")
            core.callLater(process_scanner_output, scanner_name, result.stdout.strip())
        else: log.info(f"[SCANNER_THREAD] {scanner_name} produced NO STDOUT.")
        if result.stderr and result.stderr.strip(): log.info(f"[SCANNER_THREAD_STDERR] {scanner_name}:\n{result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        log.error(f"[SCANNER_THREAD_TIMEOUT] {scanner_name} timed out.")
        with _scan_cycle_lock: _current_scan_cycle_results.append( ({"scanner": scanner_name, "vulnerability": "scanner_timeout", "ip":"N/A", "details": f"{scanner_name} timed out.", "severity":"ERROR"}, "Scanner Execution", "Timeout") )
    except Exception as e:
        log.error(f"[SCANNER_THREAD_EXCEPTION] Error running {scanner_name}: {e}", exc_info=True)
        with _scan_cycle_lock: _current_scan_cycle_results.append( ({"scanner": scanner_name, "vulnerability": "scanner_error", "ip":"N/A", "details": f"Error: {e}", "severity":"ERROR"},"Scanner Execution","Exception") )
    finally: core.callLater(_external_scanner_completed_callback)


def run_scanners(): 
    global _external_scanners_dispatched, _external_scanners_completed
    global _fixers_dispatched_this_cycle, _fixers_completed_this_cycle
    global _scan_cycle_active, mac_to_ip_table # Add mac_to_ip_table here

    # --- Discover Target IPs ---
    # Use IPs learned from network traffic. Filter out "N/A" or non-IPAddr objects if any.
    discovered_ips = [str(ip) for ip in mac_to_ip_table.values() if isinstance(ip, IPAddr)]
    # Fallback if no IPs learned yet, or provide a default set from config for initial scan
    if not discovered_ips:
        log.warning("[SCANNER_DISPATCH] No IPs learned from traffic yet. Scanners might have no targets or use defaults.")
        # Optionally, you could have a default list in sentinel_config.json for the very first scan
        # discovered_ips = config.get("scanning", {}).get("default_target_ips", [])

    with _scan_cycle_lock:
        if _scan_cycle_active:
            log.warning("[SCANNER_DISPATCH] Scan cycle already active. Skipping.")
            return
        log.info("[SCANNER_DISPATCH] Starting new scan cycle.")
        _external_scanners_dispatched = 0; _external_scanners_completed = 0
        _fixers_dispatched_this_cycle = 0; _fixers_completed_this_cycle = 0
        _scan_cycle_active = True 

    # _scanners_to_run_names is loaded from sentinel_config.json globally
    if not _scanners_to_run_names:
        log.info("[SCANNER_DISPATCH] No scanner scripts listed in _scanners_to_run_names from config.")
        with _scan_cycle_lock: _scan_cycle_active = False
        _check_if_scan_cycle_fully_complete(); return

    if not discovered_ips:
        log.info("[SCANNER_DISPATCH] No target IPs discovered or specified for scanners for this cycle.")
        # Output a status that can be picked by process_scanner_output if needed
        # Or simply complete the cycle if no scanners can be run.
        # For now, if no IPs, we'll assume scanners will handle empty target list gracefully or exit.
        # The scanner scripts above now output a status if no IPs are given.
        # We still need to "dispatch" them so the cycle completion logic works.
        # Alternative: if not discovered_ips and not default_ips_from_config: complete cycle.

    scanners_commands = {}
    for scanner_script_name in _scanners_to_run_names:
        if scanner_script_name: # Make sure name is not empty
            base_command = ["python3", os.path.join(iot_sentinel_scanners_path, scanner_script_name)]
            # Add discovered IPs as arguments if any, otherwise scanner runs with no IP args
            # (Scanners are now designed to handle this by printing a status)
            full_command = base_command + discovered_ips 
            scanners_commands[scanner_script_name] = full_command
            
    if not scanners_commands: # Should be caught by _scanners_to_run_names check, but good failsafe
        log.info("[SCANNER_DISPATCH] No scanner commands constructed.")
        with _scan_cycle_lock: _scan_cycle_active = False
        _check_if_scan_cycle_fully_complete(); return

    _external_scanners_dispatched = len(scanners_commands)
    log.debug(f"[SCANNER_DISPATCH] Expecting {_external_scanners_dispatched} scanner threads for IPs: {discovered_ips if discovered_ips else 'None'}.")
    
    for scanner_name, command in scanners_commands.items():
        threading.Thread(target=_execute_scanner_threaded, args=(scanner_name, command), daemon=True).start()

def _process_command_queue():
    if not os.path.exists(COMMAND_QUEUE_PATH): return
    commands = []
    try:
        with open(COMMAND_QUEUE_PATH, 'r+') as f:
            for line in f:
                if line.strip(): commands.append(json.loads(line))
            f.seek(0); f.truncate()
        if commands: log.debug(f"Read and cleared {len(commands)} commands from {COMMAND_QUEUE_PATH}")
    except Exception as e: log.error(f"Error processing command queue {COMMAND_QUEUE_PATH}: {e}"); return
    for cmd_data in commands: orchestrate_fixer(cmd_data)

def _recurring_scanner_loop_task(interval_seconds_arg):
    global _scan_timer, _scan_cycle_active 
    _process_command_queue()
    with _scan_cycle_lock: 
        if _scan_cycle_active: 
            log.warning("[SCHEDULER] Previous scan cycle active. Rescheduling.")
            if core.running:
                if _scan_timer: _scan_timer.cancel() 
                _scan_timer = core.callDelayed(interval_seconds_arg, _recurring_scanner_loop_task, interval_seconds_arg)
            return
    if _network_fully_up: run_scanners() 
    else: log.info("[SCHEDULER] Network not up, skipping scan.")
    if core.running:
        if _scan_timer: _scan_timer.cancel() 
        _scan_timer = core.callDelayed(interval_seconds_arg, _recurring_scanner_loop_task, interval_seconds_arg)
        log.info(f"[SCHEDULER] Next scan cycle in {interval_seconds_arg}s.")

def _initial_scanner_task(interval_seconds_arg):
    global _scan_timer 
    _process_command_queue() 
    if _network_fully_up: run_scanners()
    else: log.info("[SCHEDULER_INIT] Network not up, skipping first scan.")
    if core.running:
        if _scan_timer: _scan_timer.cancel()
        _scan_timer = core.callDelayed(interval_seconds_arg, _recurring_scanner_loop_task, interval_seconds_arg)
        log.info(f"[SCHEDULER_INIT] Recurring scans scheduled every {interval_seconds_arg}s.")

def _execute_fixer_threaded(fixer_name, command_args, original_scan_result_data):
    global _current_scan_cycle_results, acl_manager 
    if fixer_name == "ddos_fixer": full_command = ["python3", os.path.join(iot_sentinel_fixers_path, f"{fixer_name}.py"), command_args[0]]
    else: full_command = ["python3", os.path.join(iot_sentinel_fixers_path, f"{fixer_name}.py")] + command_args
    
    log_command = list(full_command) # For logging with redacted passwords
    if 'found_password' in original_scan_result_data and original_scan_result_data.get('found_password') in log_command:
        try: log_command[log_command.index(original_scan_result_data['found_password'])] = '********'
        except ValueError: pass
    elif fixer_name == 'port_closer' and len(log_command) > 5 and len(command_args) > 4: # Check ssh_pass (index 4 in command_args, 5 in full_command)
        if log_command[5] == command_args[4]: log_command[5] = '********'

    log.info(f"[FIXER_THREAD] Starting: {fixer_name} for IP {original_scan_result_data.get('ip')} cmd: {' '.join(log_command)}")
    action_description = f"Ran fixer '{fixer_name}' for IP '{original_scan_result_data.get('ip', 'N/A')}'"
    if "username" in original_scan_result_data and fixer_name != "ddos_fixer": action_description += f" user '{original_scan_result_data['username']}'"
    
    outcome_message = f"Fixer '{fixer_name}' unknown outcome."
    fix_successful = False
    try:
        result = subprocess.run(full_command, capture_output=True, text=True, check=False, timeout=180)
        if result.stdout and result.stdout.strip():
            log.debug(f"[FIXER_THREAD_STDOUT] {fixer_name}: {result.stdout.strip()}")
            parsed_json = json.loads(result.stdout.strip())
            fix_successful = parsed_json.get("success", False)
            outcome_message = parsed_json.get("message", "No message from fixer.")
            if fixer_name == "ssh_fixer" and fix_successful and "new_password_generated" in parsed_json:
                outcome_message += f" New password: {parsed_json['new_password_generated']}"
            elif fixer_name == "ddos_fixer" and fix_successful:
                ips_to_block = parsed_json.get("ips_suggested_for_blocking", [])
                if ips_to_block:
                    blocked = []
                    for ip_b in ips_to_block: acl_manager.add_rule(ip_b, "ANY", "ANY", "deny"); blocked.append(f"Denied {ip_b}")
                    outcome_message += f" POX ACLs: {'; '.join(blocked)}."
        elif result.stderr:
            outcome_message = f"Fixer error: {result.stderr.strip()[:200]}" # Limit length
        else:
            outcome_message = f"Fixer {fixer_name} no stdout. RC: {result.returncode}."
            if result.returncode == 0 : fix_successful = True # Assume success if RC 0 and no output

        if result.stderr and result.stderr.strip() and not fix_successful: # Append stderr if an error
            log.info(f"[FIXER_THREAD_STDERR] {fixer_name}: {result.stderr.strip()}")
            if "Stderr:" not in outcome_message: outcome_message += f" (Stderr: {result.stderr.strip()[:200]})"

        if fixer_name == "port_closer" and not fix_successful and len(command_args) >=3:
            target_ip, port_str, proto_str = command_args[0], command_args[1], command_args[2]
            try:
                port_int = int(port_str); proto_num = 6 if proto_str.lower() == "tcp" else 17 if proto_str.lower() == "udp" else None
                if proto_num:
                    acl_manager.add_rule(target_ip, port_int, proto_num, action="deny")
                    outcome_message += f" POX ACL to block {target_ip}:{port_int}/{proto_str} applied."
            except Exception as e_acl: log.error(f"Port_closer ACL fallback error: {e_acl}")
    except subprocess.TimeoutExpired: outcome_message = f"Fixer '{fixer_name}' timed out."; fix_successful = False
    except FileNotFoundError: outcome_message = f"Fixer script '{fixer_name}.py' not found."; fix_successful = False
    except Exception as e: outcome_message = f"Exception running '{fixer_name}': {str(e)}"; fix_successful = False
    
    log_level = log.info if fix_successful else log.warning
    log_level(f"[FIXER_OUTCOME] Fixer '{fixer_name}' for IP '{original_scan_result_data.get('ip')}': Success={fix_successful}, Msg='{outcome_message}'")
    with _scan_cycle_lock:
        _current_scan_cycle_results.append((original_scan_result_data, action_description, outcome_message))
    core.callLater(_fixer_thread_completed_callback, fixer_name)

def orchestrate_fixer(scan_result_data):
    global _fixers_dispatched_this_cycle, _current_scan_cycle_results
    vuln_type = scan_result_data.get("vulnerability"); ip = scan_result_data.get("ip")
    ports = scan_result_data.get("ports", [])
    if not vuln_type or not ip: log.warning("[FIXER_ORCHESTRATOR] Missing vuln_type or IP."); return

    fixer_name, fixer_args = None, []
    action_desc_if_no_fixer = f"Identified '{vuln_type}' on {ip} (Ports: {ports})."
    outcome_if_no_fixer = "No specific auto-fixer configured."
    ssh_user, ssh_pass = "user", "password" # Defaults, consider making configurable

    if vuln_type == "weak_ssh_credentials":
        user, pwd = scan_result_data.get("username"), scan_result_data.get("found_password")
        if user and pwd is not None: fixer_name, fixer_args = "ssh_fixer", [ip, user, pwd]
    elif vuln_type == "open_telnet_port" or (vuln_type == "open_ports" and 23 in ports):
        fixer_name, fixer_args = "port_closer", [ip, "23", "tcp", ssh_user, ssh_pass]
    elif vuln_type == "open_ports" and 80 in ports and ip == "10.0.0.4": # Specific for h4
        fixer_name, fixer_args = "port_closer", [ip, "80", "tcp", ssh_user, ssh_pass]
    # Add other specific "open_ports" handling here if needed, e.g., for MQTT on broker (though usually desired open)
    # elif vuln_type == "open_ports" and 1883 in ports and ip == "10.0.0.100":
    #     log.info(f"MQTT port 1883 open on broker {ip}. No action taken by default.") 
    elif vuln_type in ["potential_syn_flood", "potential_connection_flood", "potential_udp_flood", "potential_icmp_flood", "potential_dos_ddos_attack", "potential_syn_packet_flood"]:
        fixer_name = "ddos_fixer"; fixer_args = [json.dumps(scan_result_data)]
        
    if fixer_name:
        with _scan_cycle_lock: _fixers_dispatched_this_cycle += 1
        threading.Thread(target=_execute_fixer_threaded, args=(fixer_name, fixer_args, scan_result_data), daemon=True).start()
    else: # No specific fixer was matched for the (vuln_type, port, ip) combination
        log.info(f"[FIXER_ORCHESTRATOR] No specific fixer dispatched for '{vuln_type}' on {ip} (Ports: {ports}). Adding to results as identified.")
        with _scan_cycle_lock:
            _current_scan_cycle_results.append((scan_result_data, action_desc_if_no_fixer, outcome_if_no_fixer))
        core.callLater(_check_if_scan_cycle_fully_complete) # Important to advance cycle state

def process_scanner_output(scanner_name, output_str):
    global _current_scan_cycle_results
    lines = output_str.strip().split('\n')
    if not lines or not output_str.strip(): log.info(f"No content from {scanner_name}."); return

    for line in lines:
        line = line.strip(); 
        if not line: continue
        try:
            data = json.loads(line)
            if data.get("status"): 
                log.info(f"[SCANNER_STATUS] {scanner_name}: {data.get('status')} (Targets: {data.get('targets_checked', 'N/A')})")
                # Do NOT add raw status messages to _current_scan_cycle_results if UI should not show them
                # If they are needed for debugging in logs, keep them, UI will filter
                # For now, let's assume they go into the master log but are filtered by UI/Email
                with _scan_cycle_lock: 
                    _current_scan_cycle_results.append((data, f"Status: {scanner_name}", data.get('status')))
                continue 
            log.warning(f"[VULN_DETECTED] From {scanner_name}: {data.get('vulnerability','N/A')} on {data.get('ip','N/A')}")
            orchestrate_fixer(data)
        except json.JSONDecodeError:
            err_data = {"scanner": scanner_name, "vulnerability": "output_error", "ip":"N/A", "details": f"Malformed JSON: {line[:100]}", "severity":"ERROR"}
            with _scan_cycle_lock: _current_scan_cycle_results.append((err_data, "Scanner Output Error", "Malformed JSON"))
        except Exception as e:
            err_data = {"scanner": scanner_name, "vulnerability": "processing_error", "ip":"N/A", "details": str(e), "severity":"ERROR"}
            with _scan_cycle_lock: _current_scan_cycle_results.append((err_data, "Scanner Processing Error", str(e)))


# _handle_PacketIn (from previous response, including L2 learning and DoS integration)
# This is the one from "Okay, I understand. You need the full _handle_PacketIn(event) function..."
# Ensure all globals it needs are defined above.

def _handle_PacketIn(event):
    global mac_to_port_table, mac_to_ip_table, acl_manager, active_switches 
    global syn_packet_volume_tracker, connection_tracker, udp_flood_tracker, icmp_flood_tracker, dos_state_lock, dos_alert_cooldown
    global _dos_logic_budget_tracker, _packet_in_stats
    global SYN_FLOOD_THRESHOLD, DOS_WINDOW_SECONDS, CONNECTION_RATE_THRESHOLD, UDP_PACKET_RATE_THRESHOLD, ICMP_PACKET_RATE_THRESHOLD 
    global _current_scan_cycle_results, _scan_cycle_active, _external_scanners_dispatched

    # --- PacketIn Rate Statistics ---
    current_time_for_stats = time.time()
    _packet_in_stats["count_since_last_log"] += 1
    if current_time_for_stats - _packet_in_stats["last_log_time"] >= _packet_in_stats["log_interval_seconds"]:
        rate = _packet_in_stats["count_since_last_log"] / (current_time_for_stats - _packet_in_stats["last_log_time"])
        log.debug(f"[PacketInStats] Approx PacketIn rate: {rate:.2f} pps. Budget tracker size: {len(_dos_logic_budget_tracker)}")
        _packet_in_stats["count_since_last_log"] = 0
        _packet_in_stats["last_log_time"] = current_time_for_stats
        if len(_dos_logic_budget_tracker) > 5000: 
            keys_to_del = [k for k,v in list(_dos_logic_budget_tracker.items()) if current_time_for_stats - v.get('window_start_time', 0) > DOS_LOGIC_BUDGET_WINDOW_SECONDS * 10]
            for k_del in keys_to_del:
                try: del _dos_logic_budget_tracker[k_del]
                except KeyError: pass 
            log.debug(f"[PacketInStats] Cleaned budget_tracker, new size: {len(_dos_logic_budget_tracker)}")

    try:
        packet = event.parsed
        if not packet.parsed: return
    except Exception as e:
        log.error("***** EXCEPTION during basic packet parsing in _handle_PacketIn: %s", str(e), exc_info=True)
        return

    dpid = event.connection.dpid
    if dpid not in mac_to_port_table: 
        mac_to_port_table[dpid] = {}
        # log.warning(f"Switch {dpid_to_str(dpid)} MAC table initialized in PacketIn for DPID {dpid}.") # Can be noisy

    if not packet.src.is_multicast:
        if mac_to_port_table[dpid].get(packet.src) != event.port:
            mac_to_port_table[dpid][packet.src] = event.port
            # log.debug(f"Switch {dpid_to_str(dpid)}: Learned/Updated MAC {packet.src} on port {event.port}")

    ip_packet = packet.find(ipv4)
    if not ip_packet: # Handle non-IP (L2 only)
        if packet.dst.is_multicast:
            event.connection.send(of.ofp_packet_out(data=event.ofp, action=of.ofp_action_output(port=of.OFPP_FLOOD), in_port=event.port))
        elif packet.dst in mac_to_port_table.get(dpid, {}):
            out_port = mac_to_port_table[dpid][packet.dst]
            if out_port != event.port:
                event.connection.send(of.ofp_packet_out(data=event.ofp, action=of.ofp_action_output(port=out_port), in_port=event.port))
        else:
            event.connection.send(of.ofp_packet_out(data=event.ofp, action=of.ofp_action_output(port=of.OFPP_FLOOD), in_port=event.port))
        return

    # --- IP Packet Processing ---
    if not packet.src.is_multicast:
         mac_to_ip_table[packet.src] = ip_packet.srcip

    tcp_packet = packet.find(tcp)
    udp_packet = packet.find(udp)
    icmp_payload = packet.find(icmp)
    current_time_dos = time.time() 
    dst_ip_str = str(ip_packet.dstip)
    src_ip_str = str(ip_packet.srcip)

    proceed_with_full_dos_logic = True
    budget_key = src_ip_str 
    source_budget_info = _dos_logic_budget_tracker.get(budget_key)
    if source_budget_info:
        if current_time_dos - source_budget_info['window_start_time'] > DOS_LOGIC_BUDGET_WINDOW_SECONDS:
            source_budget_info['count'] = 1; source_budget_info['window_start_time'] = current_time_dos
        elif source_budget_info['count'] >= DOS_LOGIC_BUDGET_PER_IP: proceed_with_full_dos_logic = False
        else: source_budget_info['count'] += 1
    else: _dos_logic_budget_tracker[budget_key] = {'count': 1, 'window_start_time': current_time_dos}

    if not proceed_with_full_dos_logic and (tcp_packet or udp_packet or icmp_payload) : 
        log.debug(f"[DOS_RATE_LIMIT] Source {src_ip_str} for {dst_ip_str} exceeded budget. Skipping DoS for this packet.")

    if proceed_with_full_dos_logic: 
        with dos_state_lock:
            if tcp_packet and tcp_packet.SYN and not tcp_packet.ACK:
                target_port = tcp_packet.dstport
                if not _is_on_cooldown("potential_syn_packet_flood", dst_ip_str, target_port): 
                    key = (dst_ip_str, target_port) 
                    syn_packet_volume_tracker.setdefault(key, {"count": 0, "window_start_time": current_time_dos, "sources": {}})
                    if current_time_dos - syn_packet_volume_tracker[key]["window_start_time"] > DOS_WINDOW_SECONDS:
                        syn_packet_volume_tracker[key] = {"count": 0, "window_start_time": current_time_dos, "sources": {}}
                    syn_packet_volume_tracker[key]["count"] += 1
                    syn_packet_volume_tracker[key]["sources"][src_ip_str] = syn_packet_volume_tracker[key]["sources"].get(src_ip_str, 0) + 1
                    if syn_packet_volume_tracker[key]["count"] > SYN_FLOOD_THRESHOLD:
                        log.critical(f"[DOS_DETECTED] SYN Flood on {dst_ip_str}:{target_port}")
                        _set_cooldown("potential_syn_packet_flood", dst_ip_str, target_port)
                        top_sources = sorted(syn_packet_volume_tracker[key]["sources"].items(), key=lambda i: i[1], reverse=True)[:5]
                        vuln_data = {"scanner": "pox_internal_dos_detector", "ip": dst_ip_str, "vulnerability": "potential_syn_packet_flood",
                                     "details": f"SYN flood: {syn_packet_volume_tracker[key]['count']} SYNs to port {target_port}",
                                     "port": target_port, "protocol": "TCP", "packet_count": syn_packet_volume_tracker[key]['count'],
                                     "prominent_sources": [{"ip":s[0], "count":s[1]} for s in top_sources], "severity":"critical"}
                        with _scan_cycle_lock:
                            _current_scan_cycle_results.append((vuln_data, f"Internal DoS: SYN Flood on {dst_ip_str}:{target_port}", "Threshold breached"))
                            if not _scan_cycle_active and _external_scanners_dispatched == 0: _scan_cycle_active = True
                        core.callLater(orchestrate_fixer, vuln_data); del syn_packet_volume_tracker[key]
            if udp_packet:
                target_port = udp_packet.dstport
                if not _is_on_cooldown("potential_udp_flood", dst_ip_str, target_port):
                    key = (dst_ip_str, target_port)
                    udp_flood_tracker.setdefault(key, {"count":0, "window_start_time":current_time_dos, "sources":{}})
                    if current_time_dos - udp_flood_tracker[key]["window_start_time"] > DOS_WINDOW_SECONDS:
                        udp_flood_tracker[key] = {"count":0, "window_start_time":current_time_dos, "sources":{}}
                    udp_flood_tracker[key]["count"] += 1
                    udp_flood_tracker[key]["sources"][src_ip_str] = udp_flood_tracker[key]["sources"].get(src_ip_str,0) + 1
                    if udp_flood_tracker[key]["count"] > UDP_PACKET_RATE_THRESHOLD:
                        log.critical(f"[DOS_DETECTED] UDP Flood on {dst_ip_str}:{target_port}")
                        _set_cooldown("potential_udp_flood", dst_ip_str, target_port)
                        top_sources = sorted(udp_flood_tracker[key]["sources"].items(), key=lambda i: i[1], reverse=True)[:5]
                        vuln_data = {"scanner": "pox_internal_dos_detector", "ip": dst_ip_str, "vulnerability": "potential_udp_flood",
                                     "details": f"UDP flood: {udp_flood_tracker[key]['count']} pkts to port {target_port}",
                                     "port": target_port, "protocol": "UDP", "packet_count": udp_flood_tracker[key]['count'],
                                     "prominent_sources": [{"ip":s[0], "count":s[1]} for s in top_sources], "severity":"critical"}
                        with _scan_cycle_lock:
                            _current_scan_cycle_results.append((vuln_data, f"Internal DoS: UDP Flood on {dst_ip_str}:{target_port}", "Threshold breached"))
                            if not _scan_cycle_active and _external_scanners_dispatched == 0: _scan_cycle_active = True
                        core.callLater(orchestrate_fixer, vuln_data); del udp_flood_tracker[key]
            if icmp_payload:
                if not _is_on_cooldown("potential_icmp_flood", dst_ip_str):
                    icmp_flood_tracker.setdefault(dst_ip_str, {"count":0, "window_start_time":current_time_dos, "sources":{}})
                    if current_time_dos - icmp_flood_tracker[dst_ip_str]["window_start_time"] > DOS_WINDOW_SECONDS:
                        icmp_flood_tracker[dst_ip_str] = {"count":0, "window_start_time":current_time_dos, "sources":{}}
                    icmp_flood_tracker[dst_ip_str]["count"] +=1
                    icmp_flood_tracker[dst_ip_str]["sources"][src_ip_str] = icmp_flood_tracker[dst_ip_str]["sources"].get(src_ip_str,0) + 1
                    if icmp_flood_tracker[dst_ip_str]["count"] > ICMP_PACKET_RATE_THRESHOLD:
                        log.critical(f"[DOS_DETECTED] ICMP Flood on {dst_ip_str}")
                        _set_cooldown("potential_icmp_flood", dst_ip_str)
                        top_sources = sorted(icmp_flood_tracker[dst_ip_str]["sources"].items(), key=lambda i: i[1], reverse=True)[:5]
                        vuln_data = {"scanner": "pox_internal_dos_detector", "ip": dst_ip_str, "vulnerability": "potential_icmp_flood",
                                     "details": f"ICMP flood: {icmp_flood_tracker[dst_ip_str]['count']} ICMP pkts",
                                     "protocol": "ICMP", "packet_count": icmp_flood_tracker[dst_ip_str]['count'],
                                     "prominent_sources": [{"ip":s[0], "count":s[1]} for s in top_sources], "severity":"critical"}
                        with _scan_cycle_lock:
                            _current_scan_cycle_results.append((vuln_data, f"Internal DoS: ICMP Flood on {dst_ip_str}", "Threshold breached"))
                            if not _scan_cycle_active and _external_scanners_dispatched == 0: _scan_cycle_active = True
                        core.callLater(orchestrate_fixer, vuln_data); del icmp_flood_tracker[dst_ip_str]
    
    dst_port_for_acl = 0
    if tcp_packet: dst_port_for_acl = tcp_packet.dstport
    elif udp_packet: dst_port_for_acl = udp_packet.dstport

    pass_source_check = acl_manager.check_acl(src_ip_str, 0, ip_packet.protocol, "source")
    pass_dest_check = acl_manager.check_acl(dst_ip_str, dst_port_for_acl, ip_packet.protocol, "destination")

    if not (pass_source_check and pass_dest_check):
        log.warning(f"[ACL_BLOCK] S{dpid_to_str(dpid)}: Drop {src_ip_str}->{dst_ip_str} (P:{dst_port_for_acl}, Proto:{ip_packet.protocol})")
        msg = of.ofp_flow_mod(match=of.ofp_match.from_packet(packet, event.port), idle_timeout=60, hard_timeout=120)
        event.connection.send(msg); return
            
    if packet.dst.is_multicast:
        log.debug(f"S{dpid_to_str(dpid)}: DstMAC {packet.dst} multicast. Flood from port {event.port}.")
        event.connection.send(of.ofp_packet_out(data=event.ofp, action=of.ofp_action_output(port=of.OFPP_FLOOD), in_port=event.port))
    elif packet.dst in mac_to_port_table.get(dpid, {}):
        out_port = mac_to_port_table[dpid][packet.dst]
        if out_port == event.port: log.warning(f"S{dpid_to_str(dpid)}: Same in/out port {out_port} for {packet.dst}. Drop."); return
        log.debug(f"S{dpid_to_str(dpid)}: Known DstMAC {packet.dst} to port {out_port}. Flow install.")
        msg = of.ofp_flow_mod(match=of.ofp_match.from_packet(packet, event.port), idle_timeout=30, hard_timeout=90)
        msg.actions.append(of.ofp_action_output(port=out_port))
        if event.ofp and hasattr(event.ofp, 'buffer_id') and event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None : msg.buffer_id = event.ofp.buffer_id
        else: 
            if event.ofp: msg.data = event.ofp
        event.connection.send(msg)
    else:
        log.debug(f"S{dpid_to_str(dpid)}: DstMAC {packet.dst} unknown. Flood from port {event.port}.")
        event.connection.send(of.ofp_packet_out(data=event.ofp, action=of.ofp_action_output(port=of.OFPP_FLOOD), in_port=event.port))


def handle_connection_up(event):
    global _network_fully_up, _scan_timer, active_switches, mac_to_port_table, _topology_save_timer
    dpid = event.dpid; dpid_str = dpid_to_str(dpid)
    log.info(f"Switch {dpid_str} has connected.")
    active_switches[dpid] = event.connection 
    mac_to_port_table[dpid] = {} 
    
    if not _network_fully_up:
        _network_fully_up = True
        log.info(f"Network UP. Scheduling first scan in {_initial_scan_delay_seconds}s.")
        if _scan_timer: _scan_timer.cancel()
        _scan_timer = core.callDelayed(_initial_scan_delay_seconds, _initial_scanner_task, _scan_interval_seconds)
        if not _topology_save_timer and core.running:
            log.info("Starting periodic topology saving.")
            _topology_save_timer = core.callDelayed(5, _save_topology_periodically)
    else:
        if core.running: save_network_topology() 

def handle_connection_down(event):
    global active_switches, mac_to_port_table, _network_fully_up, _topology_save_timer
    dpid = event.dpid
    dpid_str = dpid_to_str(dpid)
    log.warning(f"Switch {dpid_str} has disconnected.")
    
    if dpid in active_switches:
        del active_switches[dpid]
    if dpid in mac_to_port_table:
        del mac_to_port_table[dpid] 
    
    if not active_switches: 
        _network_fully_up = False
        log.info("All switches disconnected. Network considered DOWN. Stopping periodic topology save timer.")
        if _topology_save_timer and core.running: # Check if core is still running before cancelling
            _topology_save_timer.cancel()
            _topology_save_timer = None
    
    # ADD THIS LINE or ensure it's called if other switches might still be up:
    # This will save the topology, which will now reflect that the switch (or all switches) are gone.
    if core.running: # Only attempt to save if POX is still running
        save_network_topology()

def launch():
    global acl_manager, dos_cleanup_timer, device_names_map 
    
    # Load Configuration from sentinel_config.json (already done at global scope, just re-accessing)
    global _initial_scan_delay_seconds, _scan_interval_seconds, _scanners_to_run_names
    global DOS_WINDOW_SECONDS, SYN_FLOOD_THRESHOLD, CONNECTION_RATE_THRESHOLD, UDP_PACKET_RATE_THRESHOLD, ICMP_PACKET_RATE_THRESHOLD
    global DOS_ALERT_COOLDOWN_SECONDS, DOS_CLEANUP_INTERVAL, DOS_LOGIC_BUDGET_PER_IP, DOS_LOGIC_BUDGET_WINDOW_SECONDS
    global _packet_in_stats


    # Ensure global 'config' dict (loaded from JSON) is used for these if not overridden by POX CLI args
    _initial_scan_delay_seconds = config.get("scanning", {}).get("initial_delay_seconds", 15)
    _scan_interval_seconds = config.get("scanning", {}).get("interval_seconds", 120)
    _scanners_to_run_names = config.get("scanning", {}).get("scanners_to_run", [])

    dos_s = config.get("dos_detection", {})
    DOS_WINDOW_SECONDS = dos_s.get("window_seconds", 10)
    SYN_FLOOD_THRESHOLD = dos_s.get("syn_flood_threshold", 20)
    # CONNECTION_RATE_THRESHOLD = dos_s.get("connection_rate_threshold", 100) # If used
    UDP_PACKET_RATE_THRESHOLD = dos_s.get("udp_flood_threshold", 200)
    ICMP_PACKET_RATE_THRESHOLD = dos_s.get("icmp_flood_threshold", 50)
    DOS_ALERT_COOLDOWN_SECONDS = dos_s.get("dos_alert_cooldown_seconds", 120)
    DOS_CLEANUP_INTERVAL = dos_s.get("dos_cleanup_interval", DOS_WINDOW_SECONDS * 2)
    DOS_LOGIC_BUDGET_PER_IP = dos_s.get("dos_logic_budget_per_ip", 1000)
    DOS_LOGIC_BUDGET_WINDOW_SECONDS = dos_s.get("dos_logic_budget_window_seconds", 1.0)
    _packet_in_stats["log_interval_seconds"] = dos_s.get("packet_in_log_interval", 5.0)


    acl_manager = ACLManager() 
    log.info("IoT Sentinel POX Component launching...")
    if not os.path.exists(acl_manager.file_path): 
        log.error(f"[CRITICAL] ACL config file missing: {acl_manager.file_path}.")
    
    try:
        with open(DEVICE_NAMES_PATH, 'r') as f:
            device_names_map = json.load(f)
        log.info(f"Successfully loaded device names from {DEVICE_NAMES_PATH}")
    except Exception as e:
        log.warning(f"Could not load device_names.json from {DEVICE_NAMES_PATH}: {e}. No custom names.")
        device_names_map = {"by_mac": {}, "by_ip": {}, "by_id": {}}

    core.openflow.addListenerByName("ConnectionUp", handle_connection_up)
    core.openflow.addListenerByName("ConnectionDown", handle_connection_down)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn) 
    
    if not dos_cleanup_timer and core.running:
         dos_cleanup_timer = core.callDelayed(DOS_CLEANUP_INTERVAL, _cleanup_dos_trackers)

    log.info("IoT Sentinel component loaded. Waiting for switch connection...")
