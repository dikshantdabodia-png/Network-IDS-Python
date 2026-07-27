from scapy.all import sniff, IP, TCP, UDP, ICMP
import os
import csv
import time
import joblib
import pandas as pd
import ipaddress
from datetime import datetime

from feature_extractor import extract_features
from geo_locator import get_geolocation


# =====================================
# PATHS
# =====================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "ids_model.pkl"
)

ENCODER_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "label_encoder.pkl"
)

CSV_FILE = os.path.join(
    BASE_DIR,
    "data",
    "features.csv"
)


# =====================================
# CONFIG
# =====================================

WINDOW_SIZE = 20
TIME_WINDOW = 4
MIN_PACKETS = 20

packet_buffer = []
destination_ports = set()

last_analysis = time.time()


# =====================================
# LOAD MODEL
# =====================================

print("Loading IDS model...")

model = joblib.load(MODEL_PATH)
encoder = joblib.load(ENCODER_PATH)

EXPECTED_COLUMNS = list(
    model.feature_names_in_
)

print("Model loaded successfully.")


# =====================================
# CREATE CSV IF NOT EXISTS
# =====================================

if not os.path.exists(CSV_FILE):

    os.makedirs(
        os.path.dirname(CSV_FILE),
        exist_ok=True
    )

    with open(
        CSV_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "timestamp",
            "source_ip",
            "destination_ip",
            "attack_type",
            "confidence",
            "risk",
            "country",
            "city",
            "region",
            "isp",
            "packet_size",
            "unique_ports",
            "packet_count",
            "tcp_count",
            "udp_count",
            "icmp_count",
            "packet_rate",
            "reason"
        ])


# =====================================
# HELPERS
# =====================================

def is_private(ip):

    try:

        ip_obj = ipaddress.ip_address(ip)

        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_multicast
        )

    except:
        return True


def choose_geo_ip(src, dst):

    if not is_private(src):
        return src

    if not is_private(dst):
        return dst

    return src


# =====================================
# RULE ENGINE
# =====================================

def detect_intrusion(packet_buffer):

    syn_count = 0
    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    for pkt in packet_buffer:

        if TCP in pkt:

            tcp_count += 1

            flags = pkt[TCP].flags

            if flags == "S":
                syn_count += 1

        elif UDP in pkt:

            udp_count += 1

        elif ICMP in pkt:

            icmp_count += 1

    unique_ports = len(
        destination_ports
    )

    packet_rate = round(
        len(packet_buffer)
        / TIME_WINDOW,
        2
    )

    # ==========================
    # PORT SCAN
    # ==========================

    if unique_ports >= 6:

        return (
            "PortScan",
            96.0,
            "HIGH",
            "High unique port access detected"
        )

    # ==========================
    # SYN FLOOD
    # ==========================

    if syn_count >= 5:

        return (
            "SYN Flood",
            94.0,
            "HIGH",
            "Abnormal TCP SYN activity"
        )

    # ==========================
    # ICMP FLOOD
    # ==========================

    if icmp_count >= 5:

        return (
            "ICMP Flood",
            91.0,
            "MEDIUM",
            "High ICMP packet volume"
        )

    # ==========================
    # UDP FLOOD
    # ==========================

    if udp_count >= 8:

        return (
            "UDP Flood",
            92.0,
            "HIGH",
            "High UDP traffic detected"
        )

    # ==========================
    # DDoS
    # ==========================

    if packet_rate > 10:

        return (
            "DDoS",
            93.0,
            "HIGH",
            "Abnormally high packet rate"
        )

    return (
        "BENIGN",
        None,
        "SAFE",
        "Traffic within baseline"
    )


# =====================================
# ML PREDICTION
# =====================================

def predict_ml(features):

    try:

        model_input = pd.DataFrame(
            [features]
        )

        model_input = model_input[
            EXPECTED_COLUMNS
        ]

        pred = model.predict(
            model_input
        )[0]

        probs = model.predict_proba(
            model_input
        )[0]

        confidence = round(
            max(probs) * 100,
            2
        )

        label = encoder.inverse_transform(
            [pred]
        )[0]

        return (
            label,
            confidence
        )

    except Exception as e:

        print(
            "Prediction error:",
            e
        )

        return (
            "UNKNOWN",
            0
        )


# =====================================
# PACKET CALLBACK
# =====================================

def packet_callback(packet):

    global last_analysis

    if IP not in packet:
        return

    packet_buffer.append(packet)

    # Track destination ports
    if TCP in packet:

        destination_ports.add(
            packet[TCP].dport
        )

    current_time = time.time()

    elapsed = (
        current_time
        - last_analysis
    )

    # Wait for batch
    if (
        len(packet_buffer)
        < WINDOW_SIZE
        and
        elapsed
        < TIME_WINDOW
    ):
        return

    if len(packet_buffer) < MIN_PACKETS:
        return

    # ======================
    # Feature Extraction
    # ======================

    features = extract_features(
        packet_buffer
    )

    if not features:

        packet_buffer.clear()
        return

    # ======================
    # ML Prediction
    # ======================

    attack_type, confidence = (
        predict_ml(features)
    )

    risk = "SAFE"
    reason = (
        "Traffic within baseline"
    )

    # ======================
    # Rule Override
    # ======================

    rule_result = detect_intrusion(
        packet_buffer
    )

    if (
        rule_result[0]
        != "BENIGN"
    ):

        attack_type = (
            rule_result[0]
        )

        confidence = (
            rule_result[1]
        )

        risk = (
            rule_result[2]
        )

        reason = (
            rule_result[3]
        )

    # ======================
    # Better Packet Selection
    # ======================

    selected_packet = None

    for pkt in reversed(
        packet_buffer
    ):

        src = pkt[IP].src
        dst = pkt[IP].dst

        # Ignore multicast noise
        if (
            dst.startswith("239.")
            or
            dst.endswith(".255")
        ):
            continue

        # Prefer external traffic
        if (
            not is_private(src)
            or
            not is_private(dst)
        ):

            selected_packet = pkt
            break

    if not selected_packet:

        selected_packet = (
            packet_buffer[-1]
        )

    source_ip = (
        selected_packet[IP].src
    )

    destination_ip = (
        selected_packet[IP].dst
    )

    geo_ip = choose_geo_ip(
        source_ip,
        destination_ip
    )

    geo = get_geolocation(
        geo_ip
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # ======================
    # Technical Stats
    # ======================

    packet_sizes = [
        len(pkt)
        for pkt
        in packet_buffer
    ]

    avg_packet_size = round(
        sum(packet_sizes)
        / len(packet_sizes),
        2
    )

    tcp_count = sum(
        1
        for pkt
        in packet_buffer
        if TCP in pkt
    )

    udp_count = sum(
        1
        for pkt
        in packet_buffer
        if UDP in pkt
    )

    icmp_count = sum(
        1
        for pkt
        in packet_buffer
        if ICMP in pkt
    )

    packet_rate = round(
        len(packet_buffer)
        / TIME_WINDOW,
        2
    )

    # ======================
    # TERMINAL OUTPUT
    # ======================

    print("\n" + "=" * 60)

    if attack_type == "BENIGN":

        print(
            f"[{timestamp}] "
            f"✓ NORMAL TRAFFIC"
        )

    else:

        print(
            f"[{timestamp}] "
            f"⚠️ INTRUSION DETECTED"
        )

    print(
        f"Type        : {attack_type}"
    )

    print(
        f"Confidence  : {confidence}%"
    )

    print(
        f"Risk Level  : {risk}"
    )

    print(
        f"Reason      : {reason}"
    )

    print(
        f"Source IP   : {source_ip}"
    )

    print(
        f"Destination : {destination_ip}"
    )

    print(
        f"Geo         : "
        f"{geo['country']}, "
        f"{geo['city']}"
    )

    print(
        f"ISP          : "
        f"{geo['isp']}"
    )

    print("=" * 60)

    # ======================
    # SAVE TO CSV
    # ======================

    with open(
        CSV_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            source_ip,
            destination_ip,
            attack_type,
            confidence,
            risk,
            geo["country"],
            geo["city"],
            geo["region"],
            geo["isp"],
            avg_packet_size,
            len(destination_ports),
            len(packet_buffer),
            tcp_count,
            udp_count,
            icmp_count,
            packet_rate,
            reason
        ])

    # Reset buffers
    packet_buffer.clear()
    destination_ports.clear()

    last_analysis = current_time


# =====================================
# START IDS
# =====================================

if __name__ == "__main__":

    print(
        "\n🚀 Smart Hybrid IDS Started"
    )

    print(
        "Monitoring traffic..."
    )

    sniff(
        prn=packet_callback,
        store=False
    )
