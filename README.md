# 🌐 IoT-Sentinel

**A comprehensive framework leveraging SDN to enhance IoT network security.**  
Features include:

- 🔍 Real-time CVE data integration  
- 🤖 Machine learning-based anomaly detection  
- 🛡️ Vulnerability scoring  
- 🧭 User-friendly application for threat detection and mitigation  

---

## 📁 Repository Structure

```
IoT-Sentinel/
├── IoTSentinel/
├── PoxFiles/
└── topologies/
```

### 📂 IoTSentinel Directory

Contains the core project files:

- **controllers/** – SDN controller scripts for managing forwarding tables and API calls  
- **fixers/** – Logic for mitigating vulnerabilities or notifying users  
- **host_scripts/** – Simulated IoT device behavior (e.g., MQTT publishing, logging)  
- **scanners/** – Network vulnerability scanning scripts  
- **servers/** – DHCP server implementation (experimental)  
- **utils/** – Utility scripts for logging, script management, etc.  
- **main.py** – Entry point and framework integration  

### 📂 PoxFiles Directory

Contains POX SDN controller scripts (e.g., `mqtt_monitor.py`).  
> ⚠️ These should be placed in `pox/pox/misc` on your Mininet VM.

### 📂 topologies Directory

Mininet topology scripts for simulating IoT networks (e.g., `iot_topo.py`).

---

## 🛠️ Tools Required

- VMware Workstation 17 Player (or alternative)
- Xming (X11 forwarding)
- PuTTY (SSH client)
- MQTT (Mosquitto broker)
- Python
- Mininet

---

## ⚙️ Setup Instructions

### 🖥️ Virtual Environment Setup

1. Install a virtualization tool (e.g., VMware)
2. Download the Mininet VM image from the Mininet website
3. Import the image into VMware
4. Configure VM:
   - Minimum 4 GB RAM
   - NAT network adapter
5. Install PuTTY and Xming
6. Enable X11 forwarding in PuTTY
7. Start the VM and SSH into it using PuTTY
8. Clone/download this repository into the Mininet VM
9. Copy `mqtt_monitor.py` into `pox/pox/misc`

---

## 🌐 Setting Up the Mininet MQTT Network

1. Run the topology:
   ```bash
   sudo python3 topologies/iot_topo.py
   ```
2. Use `xterm` or run commands like:
   ```bash
   h1 ls -a
   ```
3. Set up MQTT:
   - **Broker**:  
     ```bash
     mosquitto -d
     ```
   - **Publisher**:  
     ```bash
     mosquitto_pub -h 10.0.0.100 -t "device/h1/telemetry" -m '{"temperature":22, "humidity":55}'
     ```
   - **Subscriber**:  
     ```bash
     mosquitto_sub -h 10.0.0.100 -t "device/h1/telemetry"
     ```

4. If needed, configure Mosquitto:
   ```conf
   listener 1883
   allow_anonymous true
   ```

5. Use `autoPub.py` in `host_scripts/` to automate publishing.

---

## 🧠 Setting Up the POX SDN Controller

1. Open two terminal windows
2. In one terminal:
   ```bash
   cd pox
   python pox.py forwarding.l2_learning misc.mqtt_monitor
   ```
3. In the other terminal, start the Mininet topology
4. Run `pingall` in Mininet to verify connectivity
5. Logs will show controller activity and ACL usage
6. Explore `IoTSentinel/controllers/` for ACL and forwarding logic
7. `mqtt_monitor.py` integrates with `controllers/` and `scanners/`
8. The controller:
   - Periodically scans for open ports and SSH
   - Attempts weak SSH logins and logs results

---

## 📝 Notes

- `cve_temp.json` contains raw NIST CVE API data  
- `cve_data.json` is the formatted version  
- `cvss_scoring.py` ranks vulnerabilities by severity  
- Some components (e.g., `main.py`, `fixers/`, `servers/`) are placeholders or under development  
- DHCP server usage is still under consideration
