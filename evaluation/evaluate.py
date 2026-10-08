import csv
import json
from collections import Counter
from pathlib import Path

from detectors.port_scan import detect_port_scans
from detectors.icmp_detector import detect_icmp_spikes
from detectors.connection_detector import detect_connection_spikes


BASE_DIR = Path(__file__).resolve().parent.parent
CAPTURES_DIR = BASE_DIR / "captures"
REPORTS_DIR = BASE_DIR / "reports"

REPORTS_DIR.mkdir(exist_ok=True)

DETECTORS = {
    "port_scan": detect_port_scans,
    "icmp_spike": detect_icmp_spikes,
    "tcp_spike": detect_connection_spikes
}


#Expected labels based on our lab experiments.
#Empty list = benign activity.
TEST_CASES = {
    "normal_traffic.pcap": [],
    "scan_test.pcap": ["port_scan"],
    "threshold_scan.pcap": ["port_scan"],
    "slow_scan.pcap": ["port_scan"],
    "repeated_port.pcap": ["tcp_spike"],
    "icmp_normal.pcap": [],
    "icmp_spike.pcap": ["icmp_spike"],
    "icmp_slow.pcap": [],
    "icmp_replies.pcap": [],
    "tcp_normal.pcap": [],
    "tcp_spike.pcap": ["tcp_spike"],
    "tcp_slow.pcap": [],
    "tcp_many_ports.pcap": ["port_scan"],
    "real_tcp_normal.pcap": [],
    "real_tcp_spike.pcap": []
}


def calculate_metrics(counts):
    tp = counts["TP"]
    fp = counts["FP"]
    tn = counts["TN"]
    fn = counts["FN"]

    def safe_divide(a, b):
        return a / b if b else None

    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": safe_divide(tp, tp + fp),
        "recall": safe_divide(tp, tp + fn),
        "accuracy": safe_divide(
            tp + tn, tp + fp + tn + fn
        )
    }


results = []
counts_by_rule = {
    name: Counter()
    for name in DETECTORS
}

tested_files = 0

for filename, expected_rules in TEST_CASES.items():

    path = CAPTURES_DIR / filename

    if not path.exists():
        print(f"SKIPPED: {filename} not found")
        continue

    tested_files += 1
    print(f"\nAnalyzing {filename}")

    for rule_name, detector in DETECTORS.items():

        alerts = detector(
            str(path),
            threshold=10,
            window=60
        )

        expected = rule_name in expected_rules
        detected = len(alerts) > 0

        if expected and detected:
            outcome = "TP"
        elif not expected and detected:
            outcome = "FP"
        elif not expected and not detected:
            outcome = "TN"
        else:
            outcome = "FN"

        counts_by_rule[rule_name][outcome] += 1

        results.append({
            "capture": filename,
            "rule": rule_name,
            "expected": expected,
            "detected": detected,
            "outcome": outcome
        })

        print(f"  {rule_name}: {outcome}")


if tested_files == 0:
    raise SystemExit(
        "No PCAP files found. Generate your test captures first."
    )


csv_path = REPORTS_DIR / "evaluation_results.csv"

with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "capture", "rule", "expected",
            "detected", "outcome"
        ]
    )
    writer.writeheader()
    writer.writerows(results)


summary = {
    name: calculate_metrics(counts)
    for name, counts in counts_by_rule.items()
}

summary_path = REPORTS_DIR / "evaluation_summary.json"

with open(summary_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=4)


print("\n========== EVALUATION SUMMARY ==========")

for name, metrics in summary.items():
    print(f"\n{name.upper()}")

    for key, value in metrics.items():
        if value is None:
            print(f"{key}: N/A")
        elif key in ("precision", "recall", "accuracy"):
            print(f"{key}: {value:.2%}")
        else:
            print(f"{key}: {value}")

print(f"\nEvaluated {tested_files} PCAP files")
print(f"Results saved to: {csv_path}")
print(f"Summary saved to: {summary_path}")
