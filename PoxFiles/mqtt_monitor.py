import sys
import os
import subprocess # For running external scanners
import threading
import json
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.util import dpid_to_str # Import dpid_to_str

# Setup paths
# Assuming IoTSentinel is in the parent directory of pox, or adjust as needed
# For example, if IoTSentinel and pox are siblings:
# base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
# If IoTSentinel is inside where pox.py is run (e.g. ~/pox/IoTSentinel)
# base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
# If IoTSentinel is at /home/mininet/IoTSentinel and pox is at /home/mininet/pox
base_dir = "/home/mininet" # As per your scanner paths

sys.path.append(os.path.join(base_dir, "IoTSentinel/controllers"))

from acl import ACLManager
from fwd_table import ForwardingTableManager

log = core.getLogger()

acl_manager = ACLManager() # This will load acl_config.json
fwd_table_manager = ForwardingTableManager()

def handle_connection_up(event):
    # Use dpid_to_str to convert the dpid to a string
    # event.dpid is available directly on ConnectionUp events
    switch_id_str = dpid_to_str(event.dpid)
    log.info(f"[POX Controller - EVENT] Switch {switch_id_str} (DPID raw: {event.dpid}) connected.")

def run_scanners():
    log.info("[SCANNER TASK] Starting scheduled scan cycle (using external scripts).")
    scanner_scripts_path = os.path.join(base_dir, "IoTSentinel/scanners/")
    
    scanners_to_run = {
        "iot_port_scanner": ["python3", os.path.join(scanner_scripts_path, "iot_scanner.py")],
        "ssh_weak_creds_scanner": ["python3", os.path.join(scanner_scripts_path, "ssh_scanner.py")]
    }

    for scanner_name, command in scanners_to_run.items():
        try:
            log.info(f"[SCANNER TASK] Running: {scanner_name} (Command: {' '.join(command)})")
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
            
            log.debug(f"[SCANNER RAW RESULT] {scanner_name} - Return Code: {result.returncode}")
            if result.stdout and result.stdout.strip():
                log.info(f"[SCANNER RAW RESULT] {scanner_name} - Stdout:\n>>>\n{result.stdout.strip()}\n<<<")
                process_scanner_output(scanner_name, result.stdout)
            else:
                log.warning(f"[SCANNER TASK] {scanner_name} produced NO JSON output to STDOUT.")
            
            if result.stderr and result.stderr.strip():
                log.info(f"[SCANNER RAW RESULT] {scanner_name} - Stderr (debug output from scanner):\n>>>\n{result.stderr.strip()}\n<<<")

        except subprocess.TimeoutExpired:
            log.error(f"[SCANNER TIMEOUT] {scanner_name} timed out.")
        except FileNotFoundError:
            log.error(f"[SCANNER ERROR] Script not found for {scanner_name}: {command[1]}")
        except Exception as e:
            log.error(f"[SCANNER EXCEPTION] Error running {scanner_name}: {e}", exc_info=True)

def process_scanner_output(scanner_name, output_str):
    log.info(f"[PROCESS_SCANNER] Attempting to process output from {scanner_name}: {output_str[:200]}...")
    lines = output_str.strip().split('\n')
    if not lines or not output_str.strip():
        log.warning(f"[PROCESS_SCANNER] No actual content in output from {scanner_name}.")
        return

    processed_one = False
    for line_num, line in enumerate(lines):
        line = line.strip()
        if not line: continue
        try:
            log.debug(f"[PROCESS_SCANNER] Processing line {line_num+1} from {scanner_name}: {line}")
            vulnerability = json.loads(line)
            processed_one = True
            
            vuln_ip = vulnerability.get('ip', 'N/A')
            vuln_type = vulnerability.get('vulnerability', 'N/A')
            details = vulnerability.get('details', 'None')
            severity = vulnerability.get('severity', 'N/A')
            ports = vulnerability.get('ports', vulnerability.get('port', 'N/A'))

            log.info(f"[VULN DETECTED BY SCANNER] Source: {scanner_name}, Type: {vuln_type}, IP: {vuln_ip}, Port(s): {ports}, Severity: {severity}, Details: {details}")

            if vuln_ip != 'N/A':
                if vuln_type == "open_ports":
                    ports_to_block = ports if isinstance(ports, list) else [ports]
                    for port_to_block in ports_to_block:
                        port_int = int(port_to_block)
                        if port_int == 23: 
                            log.warning(f"[ACTION] Scanner {scanner_name} found open Telnet port {port_int} on {vuln_ip}. Adding DENY rule.")
                            acl_manager.add_rule(vuln_ip, port_int, 6, action="deny")
                        elif port_int == 80 and vuln_ip != "10.0.0.100":
                            log.warning(f"[ACTION] Scanner {scanner_name} found open HTTP port {port_int} on {vuln_ip} (non-broker). Adding DENY rule.")
                            acl_manager.add_rule(vuln_ip, port_int, 6, action="deny")
                elif vuln_type == "weak_ssh":
                    log.warning(f"[ACTION] Scanner {scanner_name} found weak SSH credentials on {vuln_ip}. Adding DENY rule for port 22.")
                    acl_manager.add_rule(vuln_ip, 22, 6, action="deny")
        except json.JSONDecodeError:
            log.error(f"[PROCESS_SCANNER_PARSE_ERROR] JSONDecodeError from {scanner_name}: '{line}'")
        except Exception as e:
            log.error(f"[PROCESS_SCANNER_ERROR] Exception from {scanner_name}: {e} - Data: '{line}'")
    
    if not processed_one and output_str.strip():
        log.error(f"[PROCESS_SCANNER] No valid JSON objects found in the output from {scanner_name}. Raw output was: {output_str.strip()}")


def _handle_PacketIn(event):
    packet = event.parsed
    if not packet.parsed: 
        # log.warning("Ignoring incomplete packet") # Can be too noisy
        return

    # Use event.dpid for the raw DPID (integer) for PacketIn events
    # Use dpid_to_str(event.dpid) for the string representation
    switch_dpid_str = dpid_to_str(event.dpid)

    ip_packet = packet.find(ipv4)
    tcp_packet = packet.find(tcp)

    if not ip_packet:
        # log.debug(f"Non-IP packet from SW {switch_dpid_str} P {event.port}, allowing l2_learning to handle.")
        return 

    log.debug(f"[PACKET_IN] SW {switch_dpid_str} P {event.port}: {ip_packet.srcip} -> {ip_packet.dstip} (Proto: {ip_packet.protocol})")
    if tcp_packet:
        log.debug(f"               TCP: {tcp_packet.srcport} -> {tcp_packet.dstport}")
        
        if tcp_packet.dstport == 23 or tcp_packet.srcport == 23:
            log.warning(f"[VULN VIA PACKET_IN] Potential Telnet: {ip_packet.srcip}:{tcp_packet.srcport} -> {ip_packet.dstip}:{tcp_packet.dstport}")
        elif tcp_packet.dstport == 22 or tcp_packet.srcport == 22:
             log.info(f"[INFO VIA PACKET_IN] Potential SSH traffic: {ip_packet.srcip}:{tcp_packet.srcport} -> {ip_packet.dstip}:{tcp_packet.dstport}")


        if acl_manager.check_acl(str(ip_packet.dstip), tcp_packet.dstport, ip_packet.protocol):
            log.info(f"[ACL ALLOW] {ip_packet.srcip}:{tcp_packet.srcport} -> {ip_packet.dstip}:{tcp_packet.dstport}")
            forwarding_entry = fwd_table_manager.get_next_hop(str(ip_packet.dstip))
            out_port = None
            if forwarding_entry and "port" in forwarding_entry: out_port = forwarding_entry["port"]
            
            if out_port is not None:
                match = of.ofp_match.from_packet(packet, event.port)
                msg = of.ofp_flow_mod()
                msg.match = match
                msg.idle_timeout = 10; msg.hard_timeout = 30
                msg.actions.append(of.ofp_action_output(port=out_port))
                
                # Include packet data if not buffered by the switch
                if event.ofp is not None and event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None :
                     msg.buffer_id = event.ofp.buffer_id
                else:
                    msg.data = event.ofp
                
                event.connection.send(msg)
                # log.debug(f"[FLOW_MOD] ALLOWED & Forwarded (fwd_table): {ip_packet.srcip} -> {ip_packet.dstip} to port {out_port}")
            else:
                log.debug(f"[FORWARDING] No fwd_table.json entry for {ip_packet.dstip}. l2_learning should handle.")
        else:
            log.warning(f"[ACL BLOCK] {ip_packet.srcip}:{tcp_packet.srcport} -> {ip_packet.dstip}:{tcp_packet.dstport}")
            # Optionally, install an explicit drop flow here
            return # Important: if blocked, don't let l2_learning also process it if it has lower priority
    else: # Non-TCP (e.g. ICMP)
        if acl_manager.check_acl(str(ip_packet.dstip), 0, ip_packet.protocol): # Port 0 for "any" port
            log.info(f"[ACL ALLOW] Non-TCP: {ip_packet.srcip} -> {ip_packet.dstip} (Proto: {ip_packet.protocol})")
        else:
            log.warning(f"[ACL BLOCK] Non-TCP: {ip_packet.srcip} -> {ip_packet.dstip} (Proto: {ip_packet.protocol})")
            return

def run_scanners_continuously(interval=60): # Scan every 60 seconds
    log.info(f"[SCHEDULER] External scanners task starting. Interval: {interval}s.")
    def _scanner_loop():
        try: run_scanners()
        except Exception as e: log.error(f"[SCHEDULER_ERROR] {e}", exc_info=True)
        core.callDelayed(interval, _scanner_loop) 
    _scanner_loop()

def launch():
    # Reduce verbosity of OpenFlow library unless debugging specific OF issues
    core.getLogger("openflow").setLevel("INFO") 
    core.getLogger("openflow.of_01").setLevel("INFO") 
    
    log.info("[IoT Sentinel POX Component] Launching...")
    if not os.path.exists(acl_manager.file_path):
        log.error(f"[CRITICAL] ACL config file missing at {acl_manager.file_path}. Using default empty ACL (likely all deny).")
    
    core.openflow.addListenerByName("ConnectionUp", handle_connection_up)
    # Process PacketIn after l2_learning (if l2_learning has default priority e.g. 0)
    # If you want this to be the primary decision maker, set priority higher (e.g. pox.core. हाई)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn, priority=0) 
    
    run_scanners_continuously()
    log.info("[IoT Sentinel POX Component] Loaded. Continuous external scanning started.")
