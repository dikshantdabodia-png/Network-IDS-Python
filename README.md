# Network-IDS-Python
A sophisticated, high-performance Network Intrusion and Traffic Analysis tool designed to monitor live network packets and provide real-time graphical insights. The project bridges the gap between raw low-level networking and high-level data visualization, making network monitoring accessible and intuitive.

🛡️ Live Network Packet Analyzer
A high-performance, real-time network monitoring tool built with Python, Scapy, and Streamlit. This application intercepts live network traffic and transforms raw packet data into an interactive, graphical dashboard for security analysis.

🚀 Features
Live Sniffing: Captures real-time packets directly from the network interface using Scapy.

Interactive Dashboard: A sleek web-based UI built with Streamlit for seamless monitoring.

Graphical Analysis: Visualizes protocol distribution (TCP, UDP, ICMP) and identifies top active Source/Destination IPs.

Real-time Updates: The dashboard reflects network changes instantly through dynamic charts (Matplotlib/Plotly).

Traffic Filtering: Capability to monitor specific protocols or ports.

🛠️ Tech Stack
Language: Python

Networking Library: Scapy

Web Framework: Streamlit

Data Analysis: Pandas, NumPy

Visualization: Matplotlib / Plotly

📸 How to Run
Follow these steps to get the project running on your local machine:

Step 1: Install Dependencies
Open your terminal and run:

Bash
pip install scapy streamlit pandas matplotlib
Step 2: Start the Packet Sniffer (Backend)
Run the sniffer script in a separate terminal.
Note: This might require Administrator/Sudo privileges to access the network interface.

Bash
python packet_sniffer.py
Step 3: Launch the Dashboard (Frontend)
Open another terminal and run the Streamlit app:

Bash
python -m streamlit run app.py
Once executed, the dashboard will automatically open in your default web browser (usually at http://localhost:8501).

📂 Project Structure
packet_sniffer.py: The core engine that captures and processes live packets.

app.py: The Streamlit script that renders the graphical dashboard.

requirements.txt: List of all necessary Python libraries.
