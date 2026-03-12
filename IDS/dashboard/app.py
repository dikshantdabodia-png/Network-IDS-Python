import streamlit as st
import pandas as pd
import os
from streamlit_autorefresh import st_autorefresh

# ---------------- Page Config ----------------
st.set_page_config(page_title="Wi‑Fi IDS Dashboard", layout="wide")
st.title("🔐 Real‑Time Wi‑Fi Intrusion Detection System")

# ---------------- Paths ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(BASE_DIR, "..", "data", "features.csv")
LOG_FILE = os.path.join(BASE_DIR, "..", "logs", "log.txt")

# ---------------- Auto Refresh ----------------
st_autorefresh(interval=2000, key="refresh")

# ---------------- Alerts ----------------
st.subheader("🚨 Intrusion Alerts")

if os.path.exists(LOG_FILE):
    with open(LOG_FILE) as f:
        logs = f.readlines()

    if logs:
        st.error("⚠️ Intrusion Detected")
        last_log = logs[-1]
        log_parts = last_log.split("|")
        
        # Safe extraction of IP, location, and organization data
        victim_ip = log_parts[3].strip().split(":")[1].strip() if len(log_parts) > 3 else "N/A"
        attacker_ip = log_parts[4].strip().split(":")[1].strip() if len(log_parts) > 4 else "N/A"
        attacker_location = log_parts[5].strip().split(":")[1].strip() if len(log_parts) > 5 else "Location unavailable"
        attacker_organization = log_parts[6].strip().split(":")[1].strip() if len(log_parts) > 6 else "Organization unavailable"
        victim_location = log_parts[7].strip().split(":")[1].strip() if len(log_parts) > 7 else "Location unavailable"
        victim_organization = log_parts[8].strip().split(":")[1].strip() if len(log_parts) > 8 else "Organization unavailable"
        
        # Display the attacker and victim information in a formatted way
        st.markdown(f"### **Attacker Information**")
        st.text(f"IP Address: {attacker_ip}")
        st.text(f"Location: {attacker_location}")
        st.text(f"ISP/Organization: {attacker_organization}")
        
        st.markdown(f"### **Victim Information**")
        st.text(f"IP Address: {victim_ip}")
        st.text(f"Location: {victim_location}")
        st.text(f"ISP/Organization: {victim_organization}")

        # Display last 5 logs
        st.text("".join(logs[-5:]))
    else:
        st.success("✅ No intrusions detected")
else:
    st.info("IDS running, waiting for alerts...")

# ---------------- Load CSV ----------------
st.subheader("📊 Live Network Traffic Analysis")

if not os.path.exists(CSV_FILE):
    st.warning("Waiting for live CSV from packet sniffer...")
    st.stop()

try:
    df = pd.read_csv(CSV_FILE, on_bad_lines="skip")

    # 🔥 CLEAN COLUMN NAMES (MOST IMPORTANT FIX)
    df.columns = df.columns.str.strip().str.lower()

    required_cols = {
        "avg_size", "tcp", "udp", "unique_ports",
        "prediction", "risk", "victim_ip", "attacker_ip", "attacker_location", "attacker_organization", "victim_location", "victim_organization"
    }

    if not required_cols.issubset(df.columns):
        st.error(f"CSV columns mismatch ❌\nFound: {list(df.columns)}")
        st.stop()

    # Convert numeric
    for col in ["avg_size", "tcp", "udp", "unique_ports", "prediction"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df.dropna(inplace=True)
    df["batch"] = range(1, len(df) + 1)

except Exception as e:
    st.error(f"CSV read error: {e}")
    st.stop()

# ---------------- Graphs ----------------
col1, col2 = st.columns(2)

with col1:
    st.line_chart(
        df.set_index("batch")[["avg_size", "tcp", "udp"]],
        use_container_width=True
    )
    st.caption("X: Time Window | Y: Packet size / Count")

with col2:
    st.line_chart(
        df.set_index("batch")[["unique_ports"]],
        use_container_width=True
    )
    st.caption("X: Time Window | Y: Unique destination ports")

# ---------------- Technical Analysis ----------------
st.subheader("⚙️ Technical Risk Analysis")

latest = df.iloc[-1]

if latest["prediction"] == 1:
    st.error("🚨 STATUS: Intrusion Detected")
else:
    st.success("✅ STATUS: Network Safe")

st.markdown(f"""
**Latest Window Analysis**
- 🔹 Avg Packet Size: `{latest['avg_size']:.2f}`
- 🔹 TCP / UDP: `{int(latest['tcp'])} / {int(latest['udp'])}`
- 🔹 Unique Ports: `{int(latest['unique_ports'])}`
- 🔹 Risk Level: **{latest['risk']}**
""")

if "attack_type" in df.columns:
    st.markdown(f"""
**Attack Explanation**
- 🛑 Type: `{latest.get('attack_type','N/A')}`
- 📌 Reason: `{latest.get('reason','N/A')}`
""")

# ---------------- About ----------------
st.divider()
st.subheader("📌 About This Project")

st.write(
    "This **Real‑Time Wi‑Fi Intrusion Detection System (IDS)** captures live network traffic, "
    "extracts behavioral features, and applies Machine Learning to detect intrusions. "
    "Unlike basic IDS, this system also explains *why* an intrusion occurred, helping "
    "security teams take faster and informed action."
)

# ---------------- Footer ----------------
st.divider()
st.markdown(
    """
    ### 👨‍💻 Developed by **DIKSHANT PRAJAPATI**

    🔗 Connect with me:  
    [📸 Instagram](#) | [📘 Facebook](#) | [💼 LinkedIn](#) | [💻 GitHub](#)

    *B.Tech Major Project — Cybersecurity & Machine Learning*
    """,
    unsafe_allow_html=True
)

st.info("Dashboard auto-updates every 2 seconds using real network traffic.")