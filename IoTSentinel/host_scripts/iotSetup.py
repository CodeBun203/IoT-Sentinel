import sys
sys.path.append('/home/mininet/.local/lib/python3.8/site-packages')

import paho.mqtt.client as mqtt
import time
import json
import os

# MQTT Broker Configuration
broker_ip = "10.0.0.100"
topic = "device/{host}/telemetry"

# Get Hostname Dynamically
hostname = os.uname()[1]  # Returns the hostname like 'h1', 'h2', etc.
print(f"Running on host: {hostname}")

# Apply Bandwidth Limits Based on Host
def set_bandwidth(hostname):
    bandwidth_limits = {
        "h1": "tc qdisc add dev h1-eth0 root tbf rate 512kbit burst 32kbit latency 50ms",
        "h2": "tc qdisc add dev h2-eth0 root tbf rate 256kbit burst 16kbit latency 50ms",
        "h3": "tc qdisc add dev h3-eth0 root tbf rate 512kbit burst 32kbit latency 50ms",
        "h4": "tc qdisc add dev h4-eth0 root tbf rate 256kbit burst 16kbit latency 50ms",
    }
    if hostname in bandwidth_limits:
        command = bandwidth_limits[hostname]
        os.system(command)
        print(f"Applied bandwidth limit: {command}")
    else:
        print(f"No bandwidth limit set for {hostname}")

set_bandwidth(hostname)

# MQTT Telemetry Publishing
client = mqtt.Client()
client.connect(broker_ip, 1883, 60)

while True:
    telemetry_data = {"temperature": 22, "humidity": 55}
    client.publish(topic.format(host=hostname), json.dumps(telemetry_data))
    print(f"Published from {hostname}: {telemetry_data}")
    time.sleep(5)
