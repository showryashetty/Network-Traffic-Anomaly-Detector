import pandas as pd
import matplotlib.pyplot as plt

# Load CSV generated from previous run
df = pd.read_csv("network_features.csv")

# Convert timestamp column to datetime
df["timestamp"] = pd.to_datetime(df["timestamp"])

# Set timestamp as index
df.set_index("timestamp", inplace=True)

# Plot packet size over time
plt.figure(figsize=(12, 6))
df["len"].plot(kind="line", color="blue", marker='o', linestyle='-')
plt.title("📊 Packet Size Over Time")
plt.xlabel("Timestamp")
plt.ylabel("Packet Size (Bytes)")
plt.grid(True)
plt.tight_layout()
plt.show()
