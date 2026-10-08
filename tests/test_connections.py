from detectors.connection_detector import detect_connection_spikes

test_cases = [
    ("tcp_normal.pcap", False),
    ("tcp_spike.pcap", True),
    ("tcp_slow.pcap", False),
    ("tcp_many_ports.pcap", False)
]

passed = 0

for filename, expected in test_cases:

    alerts = detect_connection_spikes(
        f"captures/{filename}",
        threshold=10,
        window=60
    )

    actual = len(alerts) > 0

    if actual == expected:
        print(f"{filename}: PASS")
        passed += 1
    else:
        print(f"{filename}: FAIL")

    print(f"Alerts: {alerts}\n")

print(f"Tests passed: {passed}/{len(test_cases)}")

assert passed == len(test_cases), "Some TCP tests failed"
