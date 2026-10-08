from detectors.icmp_detector import detect_icmp_spikes

test_cases = [
    ("icmp_normal.pcap", False),
    ("icmp_spike.pcap", True),
    ("icmp_slow.pcap", False),
    ("icmp_replies.pcap", False)
]

passed = 0

for filename, expected_alert in test_cases:

    alerts = detect_icmp_spikes(
        f"captures/{filename}",
        threshold=10,
        window=60
    )

    actual_alert = len(alerts) > 0
    success = actual_alert == expected_alert

    status = "PASS" if success else "FAIL"

    print(f"\n{filename}: {status}")
    print(f"Alerts: {alerts}")

    if success:
        passed += 1

print(f"\nTests passed: {passed}/{len(test_cases)}")

assert passed == len(test_cases), "Some ICMP tests failed"
