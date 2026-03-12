def extract_features(packet_list):
    features = {
        "packet_count": len(packet_list),
        "tcp_count": sum(1 for p in packet_list if p[1].proto == 6),   # TCP
        "udp_count": sum(1 for p in packet_list if p[1].proto == 17),  # UDP
        "icmp_count": sum(1 for p in packet_list if p[1].proto == 1),  # ICMP
        "avg_packet_size": sum(len(p[0]) for p in packet_list)/len(packet_list) if packet_list else 0
    }
    return features