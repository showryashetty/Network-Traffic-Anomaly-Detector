import pandas as pd

# Load captured features
df = pd.read_csv("network_features.csv")

# Example rules:
suspicious_ports = [23, 135, 445, 6667, 31337]  # Telnet, NetBIOS, IRC, etc.
safe_ports = [80, 443, 53, 22]

print("\n🚨 Potential Anomalies Detected:\n")

# Rule 1: Suspicious Destination Ports
anomaly1 = df[df['dst_port'].isin(suspicious_ports)]
print("1️⃣ Suspicious destination ports:")
print(anomaly1 if not anomaly1.empty else "✅ No issues found.\n")

# Rule 2: Unusual Packet Sizes (e.g., > 1000 bytes)
anomaly2 = df[df['packet_length'] > 1000]
print("\n2️⃣ Large packets:")
print(anomaly2 if not anomaly2.empty else "✅ No oversized packets.\n")

# Rule 3: Same IP contacted too often
ip_counts = df['dst_ip'].value_counts()
frequent_ips = ip_counts[ip_counts > 10]
print("\n3️⃣ Repeated connections to same IP:")
print(frequent_ips if not frequent_ips.empty else "✅ No excessive IP contact.\n")
