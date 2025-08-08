# IoT Sentinel: An Automated SDN Security Framework

A proactive security framework that leverages Software-Defined Networking (SDN) to automatically detect, remediate, and report on vulnerabilities in Internet of Things (IoT) networks.

---

### Table of Contents
* [About The Project](#about-the-project)
* [Project Architecture](#project-architecture)
* [Built With](#built-with)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Environment Setup](#environment-setup)
  * [Project Installation](#project-installation)
* [Usage](#usage)
* [Troubleshooting & Developer Notes](#troubleshooting--developer-notes)
* [License](#license)
* [Contact](#contact)

---

## About The Project

The rapid proliferation of IoT devices has outpaced security, leaving networks exposed to widespread attacks. Devices are frequently deployed with critical vulnerabilities such as weak default credentials, unpatched firmware, and insecure open ports.

IoT Sentinel addresses this challenge by providing a centralized, automated, and proactive defense. By creating a high-speed communication channel between the network's data and control planes, this framework can intelligently:

* **Discover:** Automatically discover active hosts on the network by learning from traffic.
* **Scan:** Dispatch a suite of security scanners to identify insecure open ports, weak credentials, and other vulnerabilities.
* **Remediate:** Automatically deploy fixer scripts to harden weak passwords, apply firewall rules, and block threats at the network level with dynamic Access Control Lists (ACLs).
* **Report:** Present all findings and actions on a centralized web dashboard and send consolidated email notifications to administrators.

---

## Project Architecture

The framework is built on a modular architecture composed of several key components:

* **POX SDN Controller:** The central brain of the system, running a custom Python module (`mqtt_monitor.py`) that orchestrates all security logic.
* **Mininet Network Emulator:** Creates a realistic virtual testbed that emulates a network of vulnerable IoT devices, switches, and services.
* **Scanners & Fixers:** A collection of standalone Python scripts designed to perform specific tasks, such as scanning for open ports or changing weak passwords.
* **Flask Web API Backend:** A lightweight Python server that acts as the bridge between the POX controller and the web UI.
* **React Frontend:** A modern, single-page web application that provides a real-time dashboard to monitor events and view network topology.

---

## Built With

* **Backend & Networking:**
    * Python
    * POX SDN Framework
    * Flask
    * Mininet
* **Frontend:**
    * React
    * JavaScript (ES6+)
    * HTML5 & CSS3
* **Protocols & Concepts:**
    * Software-Defined Networking (SDN)
    * OpenFlow
    * TCP/IP
    * MQTT

---

## Getting Started

Follow these steps to set up the development environment and get the project running.

### Prerequisites

* **Virtualization Software:** A tool to run the Mininet VM, such as **VMware Workstation Player** or VirtualBox.
* **Mininet VM:** Download the official Mininet VM image from the [Mininet Website](http://mininet.org/download/).
* **SSH Client:** **PuTTY** or another terminal for SSH access.
* **X Server:** An X11 server for Windows to forward the Mininet GUI, such as **Xming**.

### Environment Setup

1.  **Import Mininet VM:** Import the downloaded Mininet image into your virtualization software (e.g., VMware).
2.  **Configure VM Settings:** Ensure the VM is configured with a minimum of **4 GB of RAM** and the network adapter is set to **NAT**.
3.  **Enable X11 Forwarding:**
    * Install and run Xming on your host machine.
    * In PuTTY, navigate to `Connection -> SSH -> X11` and check the box for **"Enable X11 forwarding"**.
4.  **SSH into VM:** Start the VM and SSH into it using PuTTY.
5.  **Verify X11 Configuration:** Check that the `DISPLAY` variable is set correctly. It should not be blank.
    ```sh
    echo $DISPLAY
    ```

### Project Installation

1.  **Clone the repository:**
    ```sh
    git clone [https://github.com/your_username/IoTSentinel.git](https://github.com/your_username/IoTSentinel.git)
    cd IoTSentinel
    ```
2.  **Install Python Dependencies:**
    *This project does not use a `requirements.txt` file. Install the necessary packages manually.*
    ```sh
    pip install flask paho-mqtt
    ```
3.  **Install Frontend Dependencies:**
    ```sh
    cd client
    npm install
    ```

---

## Usage

To run the full application, you will need to open **four separate PuTTY terminals** connected to your Mininet VM.

**1. Start the POX Controller**
```sh
cd ~/pox
./pox.py misc.mqtt_monitor
```

**2. Start the Flask Backend**
```sh
cd ~/IoTSentinel
python3 main.py
```

**3. Start the React Frontend**
```sh
cd ~/IoTSentinel/client
npm run dev -- --host
```
*After it starts, take note of the `Network:` URL provided (e.g., `http://192.168.X.X:5173`).*

**4. Start the Mininet Network**
```sh
cd ~/IoTSentinel/topologies 
sudo python3 iot_topo.py
```
*Once the `mininet>` prompt appears, the network is running.*

**Accessing the Dashboard**

Open a web browser on your **host machine** (not inside the VM) and navigate to the `Network:` URL from Step 3. You should now see the IoT Sentinel dashboard.

---

## Troubleshooting & Developer Notes

These notes document the debugging process and solutions implemented throughout the project's development.

<details>
<summary><strong>Phase 1: Initial Network & MQTT Setup</strong></summary>

* **NAT Configuration:**
    * **Problem:** NAT interfaces were not correctly configured with IP addresses.
    * **Fix:** Assigned IPs to NAT interfaces directly in the topology script (`iot_topo.py`).
    * **Key File:** `iot_topo.py` (contains NAT setup, IP assignment, and forwarding rules).
* **IP Forwarding:**
    * **Problem:** NAT was not forwarding packets because `net.ipv4.ip_forward` was disabled.
    * **Fix:** Enabled IP forwarding on the NAT node: `sudo sysctl -w net.ipv4.ip_forward=1`.
* **iptables Rules for NAT:**
    * **Problem:** NAT forwarding and POSTROUTING rules were missing.
    * **Fix:** Added forwarding and NAT rules using `iptables` to allow packets to traverse the subnets.
* **Default Gateway Configuration:**
    * **Problem:** Hosts in one subnet lacked a default route to the other.
    * **Fix:** Added default gateways in `iot_topo.py` to ensure cross-subnet communication.
* **Mosquitto Broker Setup:**
    * **Problem:** Mosquitto broker was not listening on port 1883.
    * **Fix:** Updated `/etc/mosquitto/mosquitto.conf` to ensure `listener 1883` and `allow_anonymous true` were set.
* **Traffic Monitoring:**
    * **Problem:** No traffic was observed on NAT interfaces during tests.
    * **Fix:** Used `tcpdump` on the NAT interfaces to confirm traffic flow and identify bottlenecks.

</details>

<details>
<summary><strong>Phase 2: POX Controller & Connectivity Debugging</strong></summary>

* **Mininet Connectivity (`pingall`):**
    * **Initial Issue:** Hosts were unable to communicate. POX logs showed packets being dropped or handled with invalid flow rules.
    * **Solution:** Refined `mqtt_monitor.py` to explicitly handle ICMP packets and use flooding (`OFPP_FLOOD`) as a fallback to guarantee initial connectivity.
* **MQTT Traffic Redirection:**
    * **Optimization:** Replaced general flooding with targeted flow rules for MQTT traffic (port 1883), redirecting it specifically to the broker to improve efficiency.
* **Enhanced Logging:**
    * **Improvement:** Added detailed logs for Ethernet, IP, and TCP layers to get better visibility into packet flow and rule installation.
* **Anomaly Monitoring:**
    * **Implementation:** Added logic to flag unexpected sources of MQTT traffic, laying the groundwork for future anomaly detection.

</details>

<details>
<summary><strong>Phase 3: ACL Logic for MQTT Traffic</strong></summary>

* **Primary Issue:** Return traffic from the broker to clients (on ephemeral ports) was being blocked by the ACLs.
* **Key Fixes:**
    * Refined ACL matching logic to correctly prioritize "ANY" rules for dynamic traffic.
    * Explicitly added rules to allow broker responses to all destinations.
    * Enhanced debug logging to confirm ACL rule matching at every step of the packet-in event.

</details>

<details>
<summary><strong>Phase 4: Final Integration & Scanner Debugging</strong></summary>

* **POX Not Registering Switches:**
    * **Issue:** Running `mqtt_monitor.py` caused POX to stop logging OpenFlow switch connections.
    * **Fix:** Added a listener for `ConnectionUp` events in the controller's `launch()` function.
* **Scanners Blocking POX Core:**
    * **Issue:** The main scanner loop was blocking POX's core event processing, preventing it from handling OpenFlow events.
    * **Fix:** Moved the scanner execution to a separate, non-blocking thread using Python's `threading` library.
* **Packet Analyzer Permissions:**
    * **Issue:** A scanner script was failing with a non-zero exit status due to permissions.
    * **Fix:** Ensured the scanner was executed with `sudo python3`.

</details>

---

## License

Distributed under the MIT License. See `LICENSE` for more information.

---

## Link

Project Link: [https://github.com/your_username/IoTSentinel](https://github.com/your_username/IoTSentinel)
