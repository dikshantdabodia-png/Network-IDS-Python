from scapy.layers.inet import TCP, UDP, ICMP
import statistics


def extract_features(packet_list):

    if len(packet_list) == 0:
        return None

    # Flow duration
    first_time = packet_list[0].time
    last_time = packet_list[-1].time

    flow_duration = (
        last_time - first_time
    ) * 1_000_000  # microseconds

    # Packet lengths
    packet_lengths = [
        len(packet)
        for packet in packet_list
    ]

    total_bytes = sum(packet_lengths)

    # Protocol counts
    tcp_packets = [
        packet for packet in packet_list
        if TCP in packet
    ]

    udp_packets = [
        packet for packet in packet_list
        if UDP in packet
    ]

    icmp_packets = [
        packet for packet in packet_list
        if ICMP in packet
    ]

    # Forward / backward packets
    total_fwd_packets = len(packet_list)
    total_backward_packets = 0

    total_fwd_length = total_bytes
    total_bwd_length = 0

    # Flow rates
    if flow_duration > 0:

        flow_seconds = (
            flow_duration / 1_000_000
        )

        flow_bytes_sec = (
            total_bytes / flow_seconds
        )

        flow_packets_sec = (
            len(packet_list)
            / flow_seconds
        )

    else:

        flow_bytes_sec = 0
        flow_packets_sec = 0

    # Packet statistics
    packet_mean = statistics.mean(
        packet_lengths
    )

    packet_std = (
        statistics.stdev(
            packet_lengths
        )
        if len(packet_lengths) > 1
        else 0
    )

    # TCP flags
    syn_count = 0
    ack_count = 0
    fin_count = 0
    psh_count = 0
    urg_count = 0

    destination_port = 0

    for packet in packet_list:

        if TCP in packet:

            destination_port = (
                packet[TCP].dport
            )

            flags = packet[TCP].flags

            if flags & 0x02:
                syn_count += 1

            if flags & 0x10:
                ack_count += 1

            if flags & 0x01:
                fin_count += 1

            if flags & 0x08:
                psh_count += 1

            if flags & 0x20:
                urg_count += 1

        elif UDP in packet:

            destination_port = (
                packet[UDP].dport
            )

    # Average packet size
    avg_packet_size = (
        total_bytes
        / len(packet_list)
    )

    # EXACT feature order
    return {

        "Destination Port":
            destination_port,

        "Flow Duration":
            flow_duration,

        "Total Fwd Packets":
            total_fwd_packets,

        "Total Backward Packets":
            total_backward_packets,

        "Total Length of Fwd Packets":
            total_fwd_length,

        "Total Length of Bwd Packets":
            total_bwd_length,

        "Flow Bytes/s":
            flow_bytes_sec,

        "Flow Packets/s":
            flow_packets_sec,

        "Packet Length Mean":
            packet_mean,

        "Packet Length Std":
            packet_std,

        "SYN Flag Count":
            syn_count,

        "ACK Flag Count":
            ack_count,

        "FIN Flag Count":
            fin_count,

        "PSH Flag Count":
            psh_count,

        "URG Flag Count":
            urg_count,

        "Average Packet Size":
            avg_packet_size
    }
