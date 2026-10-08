import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter


def save_alerts(alerts, pcap_file, output_file=None):
    #Create the logs folder if it doesn't exist
    logs_folder = Path("logs")
    logs_folder.mkdir(exist_ok=True)

    #Give each PCAP its own JSON output file
    if output_file is None:
        filename = Path(pcap_file).stem + "_alerts.json"
        output_path = logs_folder / filename
    else:
        output_path = Path(output_file)
        output_path.parent.mkdir(
            parents=True, exist_ok=True
        )

    #Count alerts by detection type
    alert_counts = Counter(
        alert["type"] for alert in alerts
    )

    #Structure of report
    report = {
        "analyzed_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "capture_file": Path(pcap_file).name,

        "total_alerts": len(alerts),

        "alerts_by_type": dict(alert_counts),

        "alerts": alerts
    }

    #Write the JSON file
    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(report, file, indent=4)

    print(f"\nAlerts saved to: {output_path}")

    return output_path
