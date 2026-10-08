import argparse
from pathlib import Path

from detectors.port_scan import detect_port_scans
from detectors.icmp_detector import detect_icmp_spikes
from detectors.connection_detector import detect_connection_spikes

from logs.alert_logger import save_alerts


def run_ids(pcap_file):

    print("\n========== NETWORK IDS ==========")
    print(f"Analyzing: {pcap_file}\n")

    # Detector 1: TCP Port Scanning
    port_alerts = detect_port_scans(
        pcap_file,
        threshold=10,
        window=60
    )

    # Detector 2: ICMP Traffic Spikes
    icmp_alerts = detect_icmp_spikes(
        pcap_file,
        threshold=10,
        window=60
    )

    # Detector 3: TCP Connection Spikes
    connection_alerts = detect_connection_spikes(
        pcap_file,
        threshold=10,
        window=60
    )

    # Combine all detection results
    all_alerts = (
        port_alerts
        + icmp_alerts
        + connection_alerts
    )

    print(f"Total alerts detected: {len(all_alerts)}")

    if not all_alerts:
        print("No suspicious patterns matched the rules.")

    for i, alert in enumerate(all_alerts, start=1):

        print(f"\n------- ALERT {i} -------")

        for key, value in alert.items():
            print(f"{key}: {value}")

    # NEW: Automatically save results
    save_alerts(all_alerts, pcap_file)

    return all_alerts


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Python Network Intrusion Detection System"
    )

    parser.add_argument(
        "pcap",
        help="Path to a PCAP file"
    )

    args = parser.parse_args()

    path = Path(args.pcap)

    if not path.is_file():
        parser.error(f"File not found: {path}")

    run_ids(str(path))
