 #Detect excessive TCP SYN packets directed at the same destination IP and port.
from collections import defaultdict, deque
from scapy.all import IP, TCP, PcapReader


def detect_connection_spikes(pcap_file, threshold=10, window=60):

    #threshold: Minimum SYN packets required and window: Time interval in seconds
    
    if threshold < 1 or window <= 0:
        raise ValueError("Threshold and window must be positive")

    connections = defaultdict(list)
    alerts = []

    # STEP 1: Read the PCAP
    with PcapReader(pcap_file) as packets:
        for packet in packets:

            if IP not in packet or TCP not in packet:
                continue

            flags = int(packet[TCP].flags)

            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)

            # Count initial SYN packets only
            if not syn or ack:
                continue

            source = packet[IP].src
            destination = packet[IP].dst
            port = int(packet[TCP].dport)
            timestamp = float(packet.time)

            key = (source, destination, port)
            connections[key].append(timestamp)

    # STEP 2: Analyze connections
    for (source, destination, port), timestamps in connections.items():

        timestamps.sort()
        recent = deque()

        for timestamp in timestamps:

            recent.append(timestamp)

            # Remove old connection attempts
            while recent and timestamp - recent[0] >= window:
                recent.popleft()

            # STEP 3: Generate alert
            if len(recent) >= threshold:

                alerts.append({
                    "type": "Excessive TCP Connection Attempts",
                    "source": source,
                    "destination": destination,
                    "destination_port": port,
                    "connection_attempts": len(recent),
                    "time_window": window,
                    "detected_at": timestamp
                })

                break

    return alerts
