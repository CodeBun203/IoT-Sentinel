import sys
import os
import subprocess
import threading
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.ethernet import ethernet

# Ensure Python can locate the controllers directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../IoTSentinel/controllers")))

# Import security modules
from acl import ACLManager
from fwd_table import ForwardingTableManager
from cve_fetcher import CVEFetcher

log = core.getLogger()

# Initialize ACL, forwarding table, and CVE fetcher
acl_manager = ACLManager()
fwd_table_manager = ForwardingTableManager()
cve_fetcher = CVEFetcher()

def handle_connection(event):
    """Handles new OpenFlow switch connections."""
    log.info(f"[OPENFLOW] Switch {event.connection.dpid} connected")

core.openflow.addListenerByName("ConnectionUp", handle_connection)  # ✅ Registers switch connections

def run_scanners():
    """Runs IoT Sentinel security scanners and logs detected vulnerabilities."""
    scanners = {
        "iot_scanner.py": ["python3", "/home/mininet/IoTSentinel/scanners/iot_scanner.py"],
        "packet_analyzer.py": ["sudo", "python3", "/home/mininet/IoTSentinel/scanners/packet_analyzer.py"],  # Requires sudo
        "ssh_scanner.py": ["python3", "/home/mininet/IoTSentinel/scanners/ssh_scanner.py"]
    }

    for scanner, command in scanners.items():
        try:
            log.info(f"[POX] Running scanner: {scanner}")
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            process_scanner_output(result.stdout)
        except subprocess.CalledProcessError as e:
            log.error(f"[ERROR] Scanner failed: {scanner} - {e}")

def process_scanner_output(scanner_output):
    """Parses scanner results and updates ACL or forwarding table as needed."""
    for line in scanner_output.split("\n"):
        log.info(f"[SCANNER OUTPUT] {line}")  # ✅ Debugging detected vulnerabilities

        if "Weak SSH" in line:
            ip = line.split()[-1]
            acl_manager.add_rule(ip, 22, 6, action="deny")
            log.warning(f"[ACL UPDATE] BLOCKED SSH on {ip}")

        if "Telnet" in line:
            ip = line.split()[-1]
            acl_manager.add_rule(ip, 23, 6, action="deny")
            log.warning(f"[ACL UPDATE] BLOCKED Telnet on {ip}")

        if "compromised" in line:
            ip = line.split()[-1]
            fwd_table_manager.quarantine_device(ip)
            log.warning(f"[FWD TABLE UPDATE] QUARANTINED {ip}")

def _handle_PacketIn(event):
    """Handles incoming packets, applies ACL, forwarding, and CVE checks."""
    log.info(f"[OPENFLOW EVENT] Switch {event.connection.dpid} received a packet.")

    packet = event.parsed
    ip_packet = packet.find(ipv4)
    tcp_packet = packet.find(tcp)

    if not ip_packet:
        log.debug("[PACKET HANDLER] Non-IP packet received, dropping.")
        return

    # Debugging: Print incoming packet details
    log.debug(f"[PACKET INFO] Source: {ip_packet.srcip}, Destination: {ip_packet.dstip}, Protocol: {ip_packet.protocol}")
    if tcp_packet:
        log.debug(f"[TCP DETECTED] Source Port: {tcp_packet.srcport}, Destination Port: {tcp_packet.dstport}")

    # ACL Check
    acl_result = acl_manager.check_acl(str(ip_packet.dstip), tcp_packet.dstport, ip_packet.protocol, "destination")
    log.debug(f"[ACL RESULT] Destination: {ip_packet.dstip}, Port: {tcp_packet.dstport}, Protocol: {ip_packet.protocol}, ALLOWED: {acl_result}")

    if tcp_packet and not acl_result:
        log.warning(f"[BLOCKED] TRAFFIC BLOCKED BY ACL: Destination {ip_packet.dstip}, Port {tcp_packet.dstport}, Protocol {ip_packet.protocol}")
        return

    # Forwarding & flow rule installation
    forwarding_entry = fwd_table_manager.get_next_hop(str(ip_packet.dstip))
    if forwarding_entry:
        match = of.ofp_match.from_packet(packet, event.port)
        msg = of.ofp_flow_mod()
        msg.match = match
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port=forwarding_entry["port"]))
        event.connection.send(msg)
        log.info(f"[FLOW RULE] INSTALLED FLOW RULE: {ip_packet.srcip} -> {ip_packet.dstip}, Port {tcp_packet.dstport}")
        return

    log.warning(f"[NO ROUTE] NO FORWARDING RULE FOUND: {ip_packet.dstip}, Flooding...")
    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)

def run_scanners_continuously(interval=30):
    """Runs scanners repeatedly every 'interval' seconds in a separate thread."""
    def _scanner_loop():
        run_scanners()
        threading.Timer(interval, _scanner_loop).start()

    threading.Thread(target=_scanner_loop, daemon=True).start()  # ✅ Runs independently without blocking POX

def launch():
    """Launches MQTT monitoring module with ACL, forwarding, CVE lookup, and security scanning."""
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.setLevel("DEBUG")
    log.info("[STARTUP] MQTT Monitor module with ACL, Forwarding Table, CVE Lookup, and Security Scanning loaded")

    # Start periodic security scanning
    run_scanners_continuously()
