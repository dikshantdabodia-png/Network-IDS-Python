from flask import Flask, render_template
import pandas as pd
import os
import webbrowser
import threading
import time

# ==========================================
# PATHS
# ==========================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

TEMPLATE_DIR = os.path.join(
    os.path.dirname(
        os.path.abspath(__file__)
    ),
    "templates"
)

STATIC_DIR = os.path.join(
    os.path.dirname(
        os.path.abspath(__file__)
    ),
    "static"
)

CSV_FILE = os.path.join(
    BASE_DIR,
    "data",
    "features.csv"
)

# ==========================================
# FLASK
# ==========================================

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR
)


# ==========================================
# READ DATA
# ==========================================

def load_data():

    if not os.path.exists(CSV_FILE):
        return pd.DataFrame()

    try:

        df = pd.read_csv(CSV_FILE)

        if df.empty:
            return df

        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            errors="coerce"
        )

        df = df.dropna(
            subset=["timestamp"]
        )

        return df

    except Exception as e:

        print(
            "CSV Read Error:",
            e
        )

        return pd.DataFrame()


# ==========================================
# DASHBOARD ROUTE
# ==========================================

@app.route("/")
def dashboard():

    df = load_data()

    if df.empty:

        return render_template(
            "index.html",
            status="NO DATA",
            status_color="gray",
            status_message="Waiting for IDS traffic...",
            logs=[],
            graph_labels=[],
            packet_sizes=[],
            unique_ports=[],
            tech={}
        )

    # ======================================
    # LAST 25 FOR GRAPHS
    # ======================================

    graph_df = df.tail(25)

    graph_labels = [
        str(t)[11:19]
        for t in graph_df["timestamp"]
    ]

    packet_sizes = (
        graph_df["packet_size"]
        .fillna(0)
        .tolist()
    )

    unique_ports = (
        graph_df["unique_ports"]
        .fillna(0)
        .tolist()
    )

    # ======================================
    # LAST ENTRY STATUS
    # ======================================

    latest = df.iloc[-1]

    attack_type = str(
        latest["attack_type"]
    )

    reason = str(
        latest["reason"]
    )

    if attack_type != "BENIGN":

        status = "⚠️ INTRUSION DETECTED"
        status_color = "red"

        status_message = (
            f"{attack_type} detected "
            f"— {reason}"
        )

    else:

        status = "✅ NORMAL TRAFFIC"
        status_color = "green"

        status_message = (
            "Traffic within normal "
            "baseline."
        )

    # ======================================
    # LAST 5 LOGS
    # ======================================

    logs = (
        df.tail(5)
        .iloc[::-1]
        .to_dict(
            orient="records"
        )
    )

    # ======================================
    # TECH ANALYSIS
    # ======================================

    recent = df.tail(10)

    tech = {

        "avg_packet_size": round(
            recent["packet_size"]
            .mean(),
            2
        ),

        "packet_rate": round(
            recent["packet_rate"]
            .mean(),
            2
        ),

        "tcp_count": int(
            recent["tcp_count"]
            .mean()
        ),

        "udp_count": int(
            recent["udp_count"]
            .mean()
        ),

        "icmp_count": int(
            recent["icmp_count"]
            .mean()
        ),

        "unique_ports": int(
            recent["unique_ports"]
            .mean()
        )
    }

    return render_template(
        "index.html",

        status=status,
        status_color=status_color,
        status_message=status_message,

        logs=logs,

        graph_labels=graph_labels,
        packet_sizes=packet_sizes,
        unique_ports=unique_ports,

        tech=tech
    )


# ==========================================
# AUTO OPEN BROWSER
# ==========================================

def open_browser():

    time.sleep(1.5)

    webbrowser.open(
        "http://127.0.0.1:5000"
    )


# ==========================================
# RUN
# ==========================================

if __name__ == "__main__":

    threading.Thread(
        target=open_browser
    ).start()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
