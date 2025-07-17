# Network-Traffic-Anomaly-Detector
The Network Traffic Anomaly Detector is a Python-based real-time monitoring tool designed to analyze network traffic for suspicious and potentially malicious behavior. It uses packet inspection (via Scapy) and a set of customizable detection rules to identify threats related to confidentiality, integrity, and authenticity.

# 🚨 Network Traffic Anomaly Detector

A real-time Python-based tool that passively monitors network traffic and detects suspicious or potentially malicious activity based on custom detection rules. Designed for cybersecurity students, enthusiasts, or SOC analysts looking to understand traffic behavior related to **confidentiality**, **integrity**, and **authenticity**.

---

## 📌 Description

The **Network Traffic Anomaly Detector** uses packet sniffing and behavioral signatures to detect network anomalies in real time. It works by inspecting live packets on your device and logging alerts when patterns match known attack signatures or security policy violations.

---

## ✅ Features

- 🔎 Real-time packet sniffing using **Scapy**
- 📡 Auto-detects your current IP (works across networks)
- 🔐 Detects common security threats like:
  - SYN Floods (TCP DoS)
  - DNS Tunneling (covert channels)
  - Blacklisted IP connections
  - Plaintext credential/data leaks
  - Port scanning behavior
  - Spoofed private IPs
  - Unencrypted protocols (FTP/Telnet)
  - UDP anomalies
  - Payload integrity anomalies

---

## ⚙️ Requirements

- Python 3.6+
- Scapy

Install dependencies with:

```bash
pip install scapy
🚀 Installation
Clone the repository:

bash
Copy code
git clone https://github.com/yourusername/network-anomaly-detector.git
cd network-anomaly-detector
Run the tool:

bash
Copy code
python network_sniffer.py
It will start monitoring your system's IP automatically and output alerts if anything suspicious is detected.

🧪 Detection Rules
Rule Type	Description
🔺 SYN Flood	More than 50 SYN packets from same IP
⚠️ DNS Tunneling	>100 DNS requests from one IP
📤 Plaintext Leak	Keywords like password, token
🔍 Port Scan	>15 unique ports accessed
🚫 Blacklisted IPs	Matches hardcoded malicious IPs
🔓 Unencrypted Protocols	Traffic on FTP (21), Telnet (23)
🛑 Payload Tampering	Sudden data jump in flow
🧨 IP Spoofing	Private IPs seen outside
🟡 High UDP Port	Suspicious UDP traffic above port 1024
🔐 Brute Force	>30 failed SYNs from same IP
📦 Large Packets	Any packet >1400 bytes

💻 Example Output
css
Copy code
📡 Monitoring traffic to/from 192.168.1.15... Press Ctrl+C to stop.

🔺 [SYN FLOOD?] High SYN rate from 192.168.1.202
⚠️ [DNS TUNNELING] Excessive DNS traffic from 192.168.1.105
📤 [PLAINTEXT DATA LEAK] Sensitive data from 192.168.1.103 → 8.8.8.8
