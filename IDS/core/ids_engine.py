from scapy.all import sniff, IP
from feature_extractor import extract_features
from joblib import load

# Load trained ML model
model = load("../ml/model.pkl")  # RandomForest placeholder

# Temporary list to store captured packets
packet_buffer = []

def packet_callback(packet):
    if IP in packet:
        packet_buffer.append((packet, packet[IP]))
    if len(packet_buffer) >= 10:  # every 10 packets, run detection
        features = extract_features(packet_buffer)
        prediction = model.predict([list(features.values())])
        if prediction[0] == 1:
            print(f"⚠️ Intrusion Detected! Features: {features}")
            with open("../logs/log.txt", "a") as f:
                f.write(f"Intrusion Detected: {features}\n")
        packet_buffer.clear()

if __name__ == "__main__":
    print("Starting IDS on Wi-Fi (Layer 3)...")
    sniff(prn=packet_callback, filter="ip")