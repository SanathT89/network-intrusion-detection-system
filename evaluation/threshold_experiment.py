from pathlib import Path

from detectors.port_scan import detect_port_scans

BASE_DIR = Path(__file__).resolve().parent.parent
PCAP_FILE = BASE_DIR / "captures" / "scan_test.pcap"

for threshold in [5, 10, 15, 25]:

    alerts = detect_port_scans(
        str(PCAP_FILE),
        threshold=threshold,
        window=60
    )

    print(
        f"Threshold: {threshold} | "
        f"Alert detected: {bool(alerts)}"
    )
