import sys
sys.path.append('/home/mininet/.local/lib/python3.8/site-packages')

import paho.mqtt.client as mqtt
import time
import json

broker_ip = "10.0.0.100"
topic = "device/h1/telemetry"

client = mqtt.Client()
client.connect(broker_ip, 1883, 60)

while True:
    telemetry_data = {"temperature": 22, "humidity": 55}
    client.publish(topic, json.dumps(telemetry_data))
    print(f"Published: {telemetry_data}")
    time.sleep(5)
