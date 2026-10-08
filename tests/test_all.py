from detectors.port_scan import detect_port_scans

test_cases = [
    ("normal_traffic.pcap", False),
    ("scan_test.pcap", True),
    ("threshold_scan.pcap", True),
    ("slow_scan.pcap", False),
    ("repeated_port.pcap", False)
]

passed = 0

for filename, expected_alert in test_cases:

    path = f"captures/{filename}"
    
    alerts = detect_port_scans(
        path,
        threshold=10,
        window=60
        #Try t=5,w=60; t=15,w=60; t=10,w=10; t=10,w=120; for best behavior changes
    )

    actual_alert = len(alerts) > 0

    success = actual_alert == expected_alert

    status = "PASS" if success else "FAIL"

    print(f"{filename}: {status}")
    print(f"  Alerts: {alerts}\n")

    if success:
        passed += 1

print(f"Tests passed: {passed}/{len(test_cases)}")
