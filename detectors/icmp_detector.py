#Detect unusually high ICMP echo-request volume.
from collections import defaultdict, deque
from scapy.all import IP, ICMP, PcapReader


def detect_icmp_spikes(pcap_file, threshold=10, window=60):
    
    #: Number of requests required for an alert and window: Time window in seconds.
    if threshold < 1 or window <= 0:
        raise ValueError("Threshold and window must be positive")

    requests = defaultdict(list)
    alerts = []

    # STEP 1: Read packets from the PCAP file
    with PcapReader(pcap_file) as packets:
        for packet in packets:

            if IP not in packet or ICMP not in packet:
                continue

            # IPv4 ICMP echo request = Type 8, Code 0
            if packet[ICMP].type != 8 or packet[ICMP].code != 0:
                continue

            source = packet[IP].src
            destination = packet[IP].dst
            timestamp = float(packet.time)

            key = (source, destination)

            requests[key].append(timestamp)

    # STEP 2: Analyze each source/destination pair
    for (source, destination), timestamps in requests.items():

        timestamps.sort()

        recent_requests = deque()  #double ended queue for timestamps of recent requests

        for timestamp in timestamps:

            recent_requests.append(timestamp)

            # Remove requests outside the time window
            while (
                recent_requests
                and timestamp - recent_requests[0] >= window
            ):
                recent_requests.popleft()

            # STEP 3: Check the detection threshold
            if len(recent_requests) >= threshold:

                alerts.append({
                    "type": "High ICMP Echo Request Volume",
                    "source": source,
                    "destination": destination,
                    "request_count": len(recent_requests),
                    "time_window": window,
                    "detected_at": timestamp
                })

                # One alert per source/destination pair
                break

    return alerts
