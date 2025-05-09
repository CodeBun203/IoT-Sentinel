import sys
sys.path.append('/home/mininet/.local/lib/python3.8/site-packages')

import paho.mqtt.client as mqtt

def on_message(client, userdata, message):
     print(f"Received: {message.topic} -> {message.payload.decode()}")

client = mqtt.Client()
client.connect("10.0.0.100", 1883)
client.subscribe("device/+/telemetry")
client.on_message = on_message

client.loop_forever()
