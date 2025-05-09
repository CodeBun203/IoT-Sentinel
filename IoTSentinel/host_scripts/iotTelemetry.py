import sys
sys.path.append('/home/mininet/.local/lib/python3.8/site-packages')

import paho.mqtt.client as mqtt
import time
import json
import os
import signal
import threading

# MQTT Broker Configuration
broker_ip = "10.0.0.100"
topic = "device/{host}/telemetry"

# Get Hostname Dynamically
hostname = os.uname()[1]
print(f"Running on host: {hostname}")

# Global Flag for Exit
should_exit = threading.Event()

# Graceful Exit Handling
def handle_exit(signum, frame):
    print("\nInterrupt received, cleaning up...")
    should_exit.set()  # Only set the exit flag

# Attach signal handler for SIGINT (Ctrl+C) and SIGTERM
signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

# Create MQTT Client with latest protocol
client = mqtt.Client(protocol=mqtt.MQTTv311)

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Connected successfully to MQTT broker at {broker_ip}")
    else:
        print(f"Failed to connect, return code {rc}")

client.on_connect = on_connect

# Connect asynchronously (non-blocking)
client.connect_async(broker_ip, 1883, 60)
client.loop_start()  # Start network loop

try:
    while not should_exit.is_set():
        telemetry_data = {"temperature": 22, "humidity": 55}
        client.publish(topic.format(host=hostname), json.dumps(telemetry_data))
        print(f"Published from {hostname}: {telemetry_data}")
        time.sleep(5)
except Exception as e:
    print(f"An unexpected error occurred: {e}")
finally:
    print("Cleaning up MQTT client...")
    client.loop_stop()
    client.disconnect()
    print("Exited cleanly.")
