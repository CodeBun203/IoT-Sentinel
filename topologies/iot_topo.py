#!/usr/bin/env python3
"""
Rendition 1: iot_topo.py using Mininet's built-in NAT class.
This script configures hosts and relies on manual service starts in xterms.
The NAT node should make Mininet hosts reachable from the VM for POX scanners.
"""

from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import RemoteController
from mininet.nodelib import NAT # <<< CORRECTED IMPORT FOR MININET'S NAT CLASS

import time
import os

class IoTSentinelTopo(Topo):
    def build(self, natIPInternal='10.0.0.254'): # Internal IP of NAT, gateway for hosts
        s1 = self.addSwitch('s1')

        # Add NAT node. cls=NAT uses Mininet's NAT functionality.
        # inNamespace=False is crucial: it places one leg of nat0 in the root namespace.
        # Mininet's NAT will also typically handle setting up routes/iptables on the VM
        # to make the internal Mininet network reachable from the root namespace.
        info(f"*** Adding NAT node (nat0) using mininet.nodelib.NAT. Internal IP for Mininet hosts: {natIPInternal}\n")
        self.addNode('nat0', cls=NAT, ip=f'{natIPInternal}/24', inNamespace=False)
        self.addLink(s1, 'nat0') # Connect switch s1 to the NAT node

        # All hosts use nat0 as their default route
        h1 = self.addHost('h1', ip='10.0.0.1/24', defaultRoute=f'via {natIPInternal}')
        h2 = self.addHost('h2', ip='10.0.0.2/24', defaultRoute=f'via {natIPInternal}') 
        h3 = self.addHost('h3', ip='10.0.0.3/24', defaultRoute=f'via {natIPInternal}')  
        h4 = self.addHost('h4', ip='10.0.0.4/24', defaultRoute=f'via {natIPInternal}')  
        broker = self.addHost('broker', ip='10.0.0.100/24', defaultRoute=f'via {natIPInternal}')
        
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(broker, s1)
        self.addLink(h3, s1) 
        self.addLink(h4, s1)

def start_network():
    if os.geteuid() != 0:
        info("Error: This script must be run as root (using sudo). Exiting.")
        return

    setLogLevel('info')
    natInternalIP = '10.0.0.254'
    topo = IoTSentinelTopo(natIPInternal=natInternalIP) 
    
    net = Mininet(
        topo=topo,
        link=TCLink,
        controller=None 
    )
    
    info("*** Adding remote controller (POX)\n")
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info("*** Starting network with Mininet NAT class\n")
    net.start() 

    broker_node = net.get('broker')
    info("*** Starting MQTT broker on 'broker' host\n")
    broker_node.cmdPrint('mosquitto -d')
    time.sleep(1)

    info("\n*** Applying Configurations for Vulnerabilities (Manual Service Start for Telnet/SSH) ***\n")
    h2_node = net.get('h2')
    h3_node = net.get('h3')
    h4_node = net.get('h4')

    # --- h2: Telnet Config ONLY ---
    info("--- h2: Configuring for Telnet (Manual service start required) ---")
    try:
        telnet_conf_line = 'telnet stream tcp nowait root /usr/sbin/tcpd /usr/sbin/in.telnetd'
        h2_node.cmdPrint(f"sed -i '/^telnet\\s*stream\\s*tcp\\s*nowait/d' /etc/inetd.conf") 
        h2_node.cmdPrint(f"echo '{telnet_conf_line}' >> /etc/inetd.conf")
        h2_node.cmdPrint("echo 'in.telnetd: ALL' > /etc/hosts.allow") 
        h2_node.cmdPrint("echo 'ALL: ALL' >> /etc/hosts.allow") 
        h2_node.cmdPrint("echo '' > /etc/hosts.deny") 
        info("h2: /etc/inetd.conf configured. To start Telnet: open 'xterm h2', then run '/usr/sbin/inetd -d'.")
    except Exception as e: info(f"h2: EXCEPTION: {e}")
    info("--- h2: Telnet config finished ---")

    # --- h3: SSH Config ONLY ---
    info("--- h3: Configuring for SSH (Manual service start required) ---")
    try:
        h3_node.cmdPrint("mkdir -p /run/sshd && chmod 0755 /run/sshd")
        h3_node.cmdPrint("ls -ld /run/sshd") 
        h3_node.cmdPrint("cp /etc/ssh/sshd_config /tmp/sshd_config_temp_backup")
        h3_node.cmdPrint("sed -i 's/^#\\s*PasswordAuthentication .*/PasswordAuthentication yes/' /tmp/sshd_config_temp_backup")
        h3_node.cmdPrint("sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /tmp/sshd_config_temp_backup")
        h3_node.cmdPrint("grep -q '^PasswordAuthentication yes' /tmp/sshd_config_temp_backup || echo 'PasswordAuthentication yes' >> /tmp/sshd_config_temp_backup")
        h3_node.cmdPrint("sed -i '/^#\\s*ListenAddress .*/d' /tmp/sshd_config_temp_backup") 
        h3_node.cmdPrint("sed -i '/^ListenAddress .*/d' /tmp/sshd_config_temp_backup")      
        h3_node.cmdPrint("echo 'ListenAddress 0.0.0.0' >> /tmp/sshd_config_temp_backup")
        h3_node.cmdPrint("cp /tmp/sshd_config_temp_backup /etc/ssh/sshd_config")
        h3_node.cmdPrint("grep -E '^PasswordAuthentication|^ListenAddress' /etc/ssh/sshd_config")
        h3_node.cmdPrint('useradd -m user || echo "User user already exists"')
        h3_node.cmdPrint('echo "user:password" | chpasswd')
        info("h3: SSH configured. To start SSH: open 'xterm h3', then run '/usr/sbin/sshd -D -d -e -p 22'.")
    except Exception as e: info(f"h3: EXCEPTION: {e}")
    info("--- h3: SSH config finished ---")

    # --- h4: HTTP (Port 80) ---
    info("--- h4: Starting HTTP server ---")
    try:
        h4_node.cmdPrint('python3 -m http.server 80 > /tmp/h4_http.log 2>&1 &')
        time.sleep(1) 
        if ":80" in h4_node.cmd('netstat -tuln'): info("h4: HTTP server LISTENING.")
        else: info("h4: HTTP server FAILED to listen.")
    except Exception as e: info(f"h4: EXCEPTION: {e}")
    info("--- h4: HTTP setup finished ---")

    info("\n*** Configurations applied. MANUAL START Telnet (h2) & SSH (h3) in xterms. ***\n")
    info("*** After manual starts, POX scanners should be able to reach hosts from the VM. ***")
    info("*** Also test connectivity from VM's main terminal (e.g., ping 10.0.0.1, ssh user@10.0.0.3) ***")
    CLI(net)
    info("*** Stopping network\n")
    net.stop()

if __name__ == "__main__":
    setLogLevel('info')
    start_network()
