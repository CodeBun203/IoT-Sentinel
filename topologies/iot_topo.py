#!/usr/bin/env python3
"""
IoT Sentinel Mininet Topology Script

This script sets up a custom Mininet topology simulating an IoT environment
with two switches, four hosts (IoT devices), an MQTT broker, and NAT functionality.
It also integrates with a remote POX controller for SDN capabilities.
"""

from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import RemoteController, Node

class IoTSentinelTopo(Topo):
    """
    Custom IoT topology with 2 switches, 4 hosts, an MQTT broker, and NAT functionality.
    """

    def build(self):
        """
        Build the custom topology.
        """
        # Create switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Create hosts (IoT devices) with CPU constraints
        h1 = self.addHost('h1', ip='10.0.0.1/24', cpu=0.25)  # 25% CPU limit
        h2 = self.addHost('h2', ip='10.0.0.2/24', cpu=0.25)  # 25% CPU limit
        h3 = self.addHost('h3', ip='10.0.1.1/24', cpu=0.1)   # 10% CPU limit
        h4 = self.addHost('h4', ip='10.0.1.2/24', cpu=0.1)   # 10% CPU limit

        # Create MQTT broker
        broker = self.addHost('broker', ip='10.0.0.100/24', cpu=0.5)  # 50% CPU limit for broker

        # Connect hosts to switches with bandwidth, delay, and packet loss constraints
        self.addLink(h1, s1, bw=1, delay='50ms')             # 1 Mbps, 50ms delay
        self.addLink(h2, s1, bw=1, delay='50ms')             # 1 Mbps, 50ms delay
        self.addLink(h3, s2, bw=0.5, delay='100ms', loss=5)  # 0.5 Mbps, 100ms delay, 5% packet loss
        self.addLink(h4, s2, bw=0.5, delay='100ms', loss=5)  # 0.5 Mbps, 100ms delay, 5% packet loss

        # Connect broker to switch 1
        self.addLink(broker, s1, bw=2, delay='20ms')         # 2 Mbps, 20ms delay

        # Connect switches together
        self.addLink(s1, s2, bw=10, delay='10ms')            # 10 Mbps, 10ms delay

def start_network():
    """
    Starts the Mininet network with NAT configuration, resource constraints, and remote controller integration.
    """
    setLogLevel('info')
    topo = IoTSentinelTopo()
    net = Mininet(
        topo=topo,
        link=TCLink,  # Traffic control
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633)  # Remote POX Controller
    )

    # Add and configure NAT
    nat = net.addHost('nat', ip='10.0.0.254/24')
    net.addLink(nat, net.get('s1'))  # Link NAT to s1
    net.addLink(nat, net.get('s2'))  # Link NAT to s2

    # Start the network
    net.start()

    # Configure NAT IPs
    nat.setIP('10.0.0.254/24', intf='nat-eth0')
    nat.setIP('10.0.1.254/24', intf='nat-eth1')

    # Enable IP forwarding on NAT
    nat.cmd('sysctl net.ipv4.ip_forward=1')

    # Apply iptables rules for NAT and forwarding
    nat.cmd('iptables -t nat -A POSTROUTING -o nat-eth0 -j MASQUERADE')
    nat.cmd('iptables -t nat -A POSTROUTING -o nat-eth1 -j MASQUERADE')
    nat.cmd('iptables -A FORWARD -i nat-eth0 -o nat-eth1 -j ACCEPT')
    nat.cmd('iptables -A FORWARD -i nat-eth1 -o nat-eth0 -j ACCEPT')

    # Add default gateways for hosts in the 10.0.0.x and 10.0.1.x subnets
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    broker = net.get('broker')
    h1.cmd('route add default gw 10.0.0.254')
    h2.cmd('route add default gw 10.0.0.254')
    h3.cmd('route add default gw 10.0.1.254')
    h4.cmd('route add default gw 10.0.1.254')
    broker.cmd('route add default gw 10.0.0.254')  # Added gateway for broker

    # Start MQTT broker
    info("*** Starting MQTT broker on 'broker' host\n")
    broker.cmd('mosquitto -d')  # Start the MQTT broker

    # Open Mininet CLI
    CLI(net)

    # Stop the network
    net.stop()

if __name__ == "__main__":
    start_network()
