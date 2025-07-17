from scapy.all import sniff, IP, TCP, UDP, Raw
import time
import socket

# === AUTO-DETECT LOCAL IP ADDRESS ===
def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        s.close()

# Use detected IP
my_ip = get_my_ip()

# === STATS AND TRACKERS ===
packet_count = 0
alert_count = 0
start_time = time.time()

syn_counts = {}
flow_payloads = {}
dns_tracker = {}
spoof_tracker = {}
failed_conn_tracker = {}

blacklisted_ips = {"45.83.64.1", "185.38.175.132"}
sensitive_keywords = [b"password", b"secret", b"credit", b"confidential", b"token", b"Authorization"]

# === PACKET CALLBACK ===
def packet_callback(packet):
    global packet_count, alert_count
    packet_count += 1

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Filter: Only monitor packets to/from this system
    if my_ip not in (src_ip, dst_ip):
        return

    proto = packet[IP].proto
    sport = packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else "N/A")
    dport = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else "N/A")

    # === 1. Large Packet Alert ===
    if len(packet) > 1400:
        alert_count += 1
        print(f"⚠️ [LARGE] {len(packet)} bytes | {src_ip} → {dst_ip}")

    # === 2. TCP Anomalies ===
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if flags == 0x02:  # SYN
            syn_counts[src_ip] = syn_counts.get(src_ip, 0) + 1
            if syn_counts[src_ip] > 50:
                alert_count += 1
                print(f"🔺 [SYN FLOOD?] High SYN rate from {src_ip}")

            failed_conn_tracker[src_ip] = failed_conn_tracker.get(src_ip, 0) + 1
            if failed_conn_tracker[src_ip] > 30:
                alert_count += 1
                print(f"🔐 [AUTH BRUTEFORCE?] Excessive SYNs from {src_ip}")

    # === 3. Port Scan Detection ===
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        key = (src_ip, dst_ip)
        spoof_tracker.setdefault(key, set()).add(dport)
        if len(spoof_tracker[key]) > 15:
            alert_count += 1
            print(f"🔍 [PORT SCAN] {src_ip} scanned >15 ports on {dst_ip}")

    # === 4. UDP High Ports ===
    if packet.haslayer(UDP) and dport and int(dport) > 1024:
        print(f"🟡 [UDP PORT > 1024] {sport} → {dport} | {src_ip} → {dst_ip}")

    # === 5. DNS Tunneling ===
    if packet.haslayer(UDP) and (sport == 53 or dport == 53):
        dns_tracker[src_ip] = dns_tracker.get(src_ip, 0) + 1
        if dns_tracker[src_ip] > 100:
            alert_count += 1
            print(f"⚠️ [DNS TUNNELING] Excessive DNS traffic from {src_ip}")

    # === 6. Sensitive Keyword Leak ===
    if packet.haslayer(Raw):
        payload = packet[Raw].load.lower()
        if any(keyword in payload for keyword in sensitive_keywords):
            alert_count += 1
            print(f"📤 [PLAINTEXT DATA LEAK] Sensitive data from {src_ip} → {dst_ip}")

    # === 7. Blacklisted IP Detection ===
    if src_ip in blacklisted_ips or dst_ip in blacklisted_ips:
        alert_count += 1
        print(f"🚫 [BLACKLISTED IP] {src_ip} ⇄ {dst_ip}")

    # === 8. Unencrypted Protocols (FTP, Telnet) ===
    if packet.haslayer(TCP) and int(dport) in [21, 23]:
        alert_count += 1
        print(f"🔓 [UNENCRYPTED PROTOCOL] {proto} on port {dport} from {src_ip}")

    # === 9. Payload Size Tampering ===
    if packet.haslayer(Raw):
        flow_key = f"{src_ip}:{sport}->{dst_ip}:{dport}"
        length = len(packet[Raw].load)
        flow_payloads.setdefault(flow_key, []).append(length)
        if len(flow_payloads[flow_key]) > 5:
            avg = sum(flow_payloads[flow_key][-5:]) / 5
            if abs(length - avg) > 1000:
                alert_count += 1
                print(f"🛑 [INTEGRITY RISK] Sudden payload size jump in {flow_key}")

    # === 10. IP Spoofing Check ===
    private_ranges = ["10.", "172.16.", "192.168."]
    if any(src_ip.startswith(p) for p in private_ranges) and src_ip != my_ip and dst_ip != my_ip:
        alert_count += 1
        print(f"🧨 [SPOOFED IP?] Private IP used externally: {src_ip}")

    # === Periodic Stats ===
    if packet_count % 50 == 0:
        print(f"\n📊 Stats - Total Packets: {packet_count}, Alerts: {alert_count}\n")

# === START SNIFFING ===
print(f"\n📡 Monitoring traffic to/from {my_ip}... Press Ctrl+C to stop.\n")
sniff(prn=packet_callback, store=0)
