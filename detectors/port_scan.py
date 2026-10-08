#Detect TCP SYN connections to multiple destination ports from one source to one destination.
from collections import defaultdict, Counter
from scapy.all import IP, TCP, PcapReader


def detect_port_scans(pcap_file, threshold=10, window=60):
    
    #threshold: minimum unique ports and window: time window in seconds
    connections = defaultdict(list)
    alerts = []

    # Read packets
    with PcapReader(pcap_file) as packets:
        for packet in packets:

            if IP not in packet or TCP not in packet:
                continue

            flags = int(packet[TCP].flags)

            # Only initial SYN packets
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)

            if not syn or ack:
                continue

            source = packet[IP].src
            destination = packet[IP].dst
            port = int(packet[TCP].dport)
            timestamp = float(packet.time)

            key = (source, destination)

            connections[key].append((timestamp, port))

    #Analyze each source/destination pair
    for (source, destination), events in connections.items():

        events.sort()

        left = 0
        port_counts = Counter()

        for right, (timestamp, port) in enumerate(events):

            port_counts[port] += 1

            # Remove packets outside the time window
            while timestamp - events[left][0] >= window:
                old_port = events[left][1]

                port_counts[old_port] -= 1

                if port_counts[old_port] == 0:
                    del port_counts[old_port]

                left += 1

            #Check if threshold is reached
            if len(port_counts) >= threshold:

                alerts.append({
                    "source": source,
                    "destination": destination,
                    "distinct_ports": len(port_counts),
                    "time_window": window,
                    "detected_at": timestamp,
                    "type": "Possible TCP Port Scan"
                })

                break  #One alert per source/destination pair

    return alerts
