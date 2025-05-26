#!/usr/bin/env python3
"""
iot_topo.py: Configures Mininet topology for IoT Sentinel.
- h1: General host, hping3 installed for testing.
- h2: Runs Telnet service.
- h3: Runs SSH service, 'user:password' created, 'user' has NOPASSWD sudo for chpasswd.
- h4: Runs HTTP server.
- broker: Runs MQTT broker.
- Hosts h1-h4 and broker are configured with static DNS servers (8.8.8.8, 1.1.1.1).
"""

from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import RemoteController
from mininet.nodelib import NAT

import time
import os

class IoTSentinelTopo(Topo):
    """Custom topology for IoT Sentinel."""
    def build(self, natIPInternal='10.0.0.254'):
        s1 = self.addSwitch('s1')

        info(f"*** Adding NAT node (nat0). Internal IP for Mininet hosts: {natIPInternal}\n")
        # inNamespace=False for nat0 to access external network
        self.addNode('nat0', cls=NAT, ip=f'{natIPInternal}/24', inNamespace=False)
        self.addLink(s1, 'nat0')

        # Add hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', defaultRoute=f'via {natIPInternal}')
        h2 = self.addHost('h2', ip='10.0.0.2/24', defaultRoute=f'via {natIPInternal}') 
        h3 = self.addHost('h3', ip='10.0.0.3/24', defaultRoute=f'via {natIPInternal}')  
        h4 = self.addHost('h4', ip='10.0.0.4/24', defaultRoute=f'via {natIPInternal}')  
        broker = self.addHost('broker', ip='10.0.0.100/24', defaultRoute=f'via {natIPInternal}')
        
        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(broker, s1)
        self.addLink(h3, s1) 
        self.addLink(h4, s1)

def start_network():
    """Starts the Mininet network with IoT Sentinel configurations."""
    if os.geteuid() != 0:
        info("Error: This script must be run as root (using sudo). Exiting.")
        return

    setLogLevel('info')
    natInternalIP = '10.0.0.254'
    topo = IoTSentinelTopo(natIPInternal=natInternalIP) 
    
    net = Mininet(
        topo=topo,
        link=TCLink,
        controller=None # Will be added manually
    )
    
    info("*** Adding remote controller (POX)\n")
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info("*** Starting network with Mininet NAT class\n")
    net.start() 

    # Get host objects
    h1_node = net.get('h1')
    h2_node = net.get('h2')
    h3_node = net.get('h3')
    h4_node = net.get('h4')
    broker_node = net.get('broker')

    # Start MQTT broker on 'broker' host
    info(f"*** Starting MQTT broker on '{broker_node.name}' host\n")
    broker_node.cmdPrint('mosquitto -d')
    time.sleep(1) # Give broker a moment to start

    info("\n*** Applying Configurations for Vulnerabilities & Services ***\n")

    # --- h1: Install hping3 for DoS testing ---
    info(f"--- {h1_node.name}: Installing hping3 for DoS testing ---")
    h1_node.cmd("apt-get update && apt-get install -y hping3")
    info(f"--- {h1_node.name}: hping3 installation attempted ---")

    # --- h2: Telnet Config ONLY ---
    info(f"--- {h2_node.name}: Configuring for Telnet (Manual service start required) ---")
    try:
        telnet_conf_line = 'telnet stream tcp nowait root /usr/sbin/tcpd /usr/sbin/in.telnetd'
        h2_node.cmdPrint(f"sed -i '/^telnet\\s*stream\\s*tcp\\s*nowait/d' /etc/inetd.conf") 
        h2_node.cmdPrint(f"echo '{telnet_conf_line}' >> /etc/inetd.conf")
        h2_node.cmdPrint("echo 'in.telnetd: ALL' > /etc/hosts.allow") 
        h2_node.cmdPrint("echo 'ALL: ALL' >> /etc/hosts.allow") 
        h2_node.cmdPrint("echo '' > /etc/hosts.deny") 
        info(f"{h2_node.name}: /etc/inetd.conf configured. To start Telnet: 'xterm {h2_node.name}', then run '/usr/sbin/inetd -d'.")
    except Exception as e: info(f"{h2_node.name}: Telnet EXCEPTION: {e}")
    info(f"--- {h2_node.name}: Telnet config finished ---")

    # --- h3: SSH Config & Sudo for 'user' to run chpasswd ---
    info(f"--- {h3_node.name}: Configuring for SSH (Manual service start required) ---")
    try:
        h3_node.cmd("apt-get update && apt-get install -y openssh-server sudo") # Ensure sudo is present
        h3_node.cmd("mkdir -p /run/sshd && chmod 0755 /run/sshd")
        
        h3_node.cmd("cp /etc/ssh/sshd_config /tmp/sshd_config_temp_backup")
        h3_node.cmd("sed -i 's/^#\\s*PasswordAuthentication .*/PasswordAuthentication yes/' /tmp/sshd_config_temp_backup")
        h3_node.cmd("sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /tmp/sshd_config_temp_backup")
        h3_node.cmd("grep -q '^PasswordAuthentication yes' /tmp/sshd_config_temp_backup || echo 'PasswordAuthentication yes' >> /tmp/sshd_config_temp_backup")
        
        h3_node.cmd("sed -i 's/^#\\s*PermitRootLogin .*/PermitRootLogin yes/' /tmp/sshd_config_temp_backup")
        h3_node.cmd("sed -i 's/^PermitRootLogin prohibit-password/PermitRootLogin yes/' /tmp/sshd_config_temp_backup")
        h3_node.cmd("grep -q '^PermitRootLogin yes' /tmp/sshd_config_temp_backup || echo 'PermitRootLogin yes' >> /tmp/sshd_config_temp_backup")

        h3_node.cmd("sed -i '/^#\\s*ListenAddress .*/d' /tmp/sshd_config_temp_backup") 
        h3_node.cmd("sed -i '/^ListenAddress .*/d' /tmp/sshd_config_temp_backup")      
        h3_node.cmd("echo 'ListenAddress 0.0.0.0' >> /tmp/sshd_config_temp_backup")
        h3_node.cmd("cp /tmp/sshd_config_temp_backup /etc/ssh/sshd_config")
        
        h3_node.cmd('useradd -m user -s /bin/bash || echo "User user already exists"')
        h3_node.cmd('echo "user:password" | chpasswd')

        sudoers_file_path = "/etc/sudoers.d/user_iot_fixer_permissions"
        h3_node.cmd(f'echo "user ALL=(ALL) NOPASSWD: /usr/sbin/chpasswd" > {sudoers_file_path}')
        h3_node.cmd(f'chmod 0440 {sudoers_file_path}') 
        
        info(f"{h3_node.name}: SSH configured for user 'user' with NOPASSWD sudo for chpasswd.")
        info(f"To start SSH on {h3_node.name}: 'xterm {h3_node.name}', then run '/usr/sbin/sshd -p 22'.")
    except Exception as e: info(f"{h3_node.name}: SSH EXCEPTION: {e}")
    info(f"--- {h3_node.name}: SSH config finished ---")

    # --- h4: HTTP (Port 80) ONLY ---
    info(f"--- {h4_node.name}: Starting HTTP server ---")
    try:
        h4_node.cmd('python3 -m http.server 80 > /tmp/h4_http.log 2>&1 &')
        time.sleep(1) 
        if ":80" in h4_node.cmd('netstat -tuln'): info(f"{h4_node.name}: HTTP server LISTENING.")
        else: info(f"{h4_node.name}: HTTP server FAILED to listen.")
    except Exception as e: info(f"{h4_node.name}: HTTP EXCEPTION: {e}")
    info(f"--- {h4_node.name}: HTTP setup finished ---")

    # --- Configuring Static DNS for Hosts ---
    info("\n--- Configuring Static DNS for Hosts (using 8.8.8.8 and 1.1.1.1) ---")
    dns_servers_conf = "nameserver 8.8.8.8\\nnameserver 1.1.1.1"
    for host_node in [h1_node, h2_node, h3_node, h4_node, broker_node]:
        info(f"Setting static DNS for {host_node.name}...")
        # The -e flag for echo interprets \n as newline.
        # Overwrite /etc/resolv.conf. This is safe in Mininet as it's per-namespace.
        host_node.cmd(f"echo -e '{dns_servers_conf}' > /etc/resolv.conf")
        # Optionally, verify:
        # host_node.cmdPrint(f"cat /etc/resolv.conf") 
    info("--- Static DNS configuration applied to relevant hosts ---")
    
    info("\n*** Configurations applied. MANUAL START Telnet (h2) & SSH (h3) in xterms if needed. ***\n")
    CLI(net)
    info("*** Stopping network\n")
    net.stop()

if __name__ == "__main__":
    start_network()
