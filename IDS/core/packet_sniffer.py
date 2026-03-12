from scapy.all import sniff, conf, IP, TCP, UDP, ICMP
from sklearn.ensemble import RandomForestClassifier
import pickle
import os
import csv
from datetime import datetime
import requests
import socket

# ----------------- CONFIG -----------------
conf.L2socket = conf.L3socket  # Force Layer 3 socket for Wi-Fi on Windows
WINDOW_SIZE = 20
MODEL_FILE = "ids_model.pkl"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOG_FILE = os.path.join(BASE_DIR, "logs", "log.txt")
CSV_FILE = os.path.join(BASE_DIR, "data", "features.csv")

# ----------------- ML MODEL -----------------
X_train = [
    [20, 20, 0, 0, 850, 4],   # Normal traffic
    [20, 18, 2, 0, 780, 7],   # Slight anomaly
    [20, 5, 15, 0, 90, 10],   # Normal traffic
    [20, 0, 0, 20, 120, 1],   # ICMP flood
    [20, 10, 10, 0, 100, 15], # Port scan
]
y_train = [0, 0, 0, 1, 1]      # 0=Normal, 1=Intrusion

if not os.path.exists(MODEL_FILE):
    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X_train, y_train)
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(clf, f)
else:
    with open(MODEL_FILE, "rb") as f:
        clf = pickle.load(f)

# ----------------- PACKET BUFFER -----------------
packet_buffer = []

# ----------------- FEATURE EXTRACTION -----------------
def extract_features(packets):
    total = len(packets)
    tcp_count = sum(1 for p in packets if TCP in p)
    udp_count = sum(1 for p in packets if UDP in p)
    icmp_count = sum(1 for p in packets if ICMP in p)
    avg_size = sum(len(p) for p in packets) / total
    unique_ports = len(set(
        [p[TCP].dport if TCP in p else (p[UDP].dport if UDP in p else 0) for p in packets]
    ))
    return [total, tcp_count, udp_count, icmp_count, avg_size, unique_ports]

# ----------------- GELOCATION FUNCTION -----------------
def get_ip_geolocation(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        
        location = f"Location: {data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}"
        organization = f"ISP/Org: {data.get('org', 'Unknown')}"  # Shows ISP or Organization
        return location, organization
    except Exception as e:
        return "Location data unavailable", "Organization data unavailable"

# ----------------- REVERSE DNS LOOKUP -----------------
def get_reverse_dns(ip):
    try:
        domain = socket.gethostbyaddr(ip)
        return domain[0]
    except socket.herror:
        return "No domain found"

# ----------------- INTRUSION EXPLANATION -----------------
def explain_intrusion(features):
    total, tcp, udp, icmp, avg_size, unique_ports = features
    if unique_ports > 15:
        return "Port Scanning Attack", "High number of unique destination ports"
    if icmp > 10:
        return "ICMP Flood Attack", "Excessive ICMP packets detected"
    if udp > tcp and udp > 15:
        return "UDP Flood Attack", "Abnormally high UDP traffic"
    if avg_size < 120:
        return "Packet Flooding", "Very small average packet size"
    if tcp > 18:
        return "TCP SYN Abuse", "Excessive TCP connections"
    return "Unknown Anomaly", "Traffic pattern deviates from baseline"

# ----------------- RISK FACTOR -----------------
def risk_factor(features, prediction):
    if prediction == 1:
        return "High"
    elif features[1] + features[2] > 25:
        return "Medium"
    else:
        return "Low"

# ----------------- PACKET CALLBACK -----------------
def packet_callback(packet):
    if IP not in packet:
        return  # Ignore non-IP packets

    victim_ip = packet[IP].dst
    attacker_ip = packet[IP].src

    packet_buffer.append(packet)

    if len(packet_buffer) >= WINDOW_SIZE:

        features = extract_features(packet_buffer)
        prediction = clf.predict([features])[0]
        risk = risk_factor(features, prediction)

        attack_type = "Normal"
        reason = "Traffic within normal baseline"

        if prediction == 1:
            attack_type, reason = explain_intrusion(features)
            attacker_location, attacker_organization = get_ip_geolocation(attacker_ip)
            victim_location, victim_organization = get_ip_geolocation(victim_ip)
        else:
            attacker_location = attacker_organization = ""
            victim_location = victim_organization = ""

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        os.makedirs("logs", exist_ok=True)

        if prediction == 1:
            print(f"[ALERT] Intrusion Detected | Features: {features}")
            with open(LOG_FILE, "a") as f:
                f.write(f"{timestamp} [ALERT] Intrusion | Features: {features}\n")
        else:
            print(f"[INFO] Normal traffic | Features: {features}")
            with open(LOG_FILE, "a") as f:
                f.write(f"{timestamp} [INFO] Normal traffic | Features: {features}\n")

        packet_buffer.clear()


# ----------------- MAIN -----------------
if __name__ == "__main__":
    print("Starting Wi-Fi packet capture + IDS prediction (real-time CSV + logs)...")
    sniff(prn=packet_callback, store=False)