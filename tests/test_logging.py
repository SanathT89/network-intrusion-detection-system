#Test verifies that the generated file contains valid JSON and that the saved alert matches the expected detection.
import json
from tempfile import TemporaryDirectory
from pathlib import Path
from logs.alert_logger import save_alerts
from run_ids import run_ids


#Run IDS against a known synthetic capture
alerts = run_ids("captures/tcp_spike.pcap")

assert len(alerts) == 1, "Expected one TCP spike alert"

#Test the logger with an isolated temporary file
with TemporaryDirectory() as temp_dir:

    output = Path(temp_dir) / "test_alerts.json"

    save_alerts(
        alerts,
        "captures/tcp_spike.pcap",
        output_file=output
    )

    assert output.exists(), "JSON file was not created"

    with open(output, encoding="utf-8") as file:
        report = json.load(file)

    assert report["total_alerts"] == 1
    assert len(report["alerts"]) == 1

    assert (
        report["alerts"][0]["type"]
        == "Excessive TCP Connection Attempts"
    )

    print("JSON logging test: PASS")
