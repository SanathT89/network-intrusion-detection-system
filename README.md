# Network Intrusion Detection System (NIDS)

A Python based, rule driven Network Intrusion Detection System designed to analyze network packet captures and identify potentially suspicious traffic patterns.

The project uses Scapy for packet analysis, configurable detection rules, JSON based alert logging, and a Streamlit dashboard for visualization.

## Features

- **TCP Port Scan Detection:** Identifies attempts to connect to multiple destination ports within a configurable time window.
- **ICMP Traffic Detection:** Detects high volumes of ICMP echo requests.
- **TCP Connection Spike Detection:** Identifies unusually frequent TCP SYN packets directed at the same destination port.
- **JSON Alert Logging:** Stores detected events in structured reports.
- **Interactive Dashboard:** Visualizes security alerts, source addresses, and detection trends.
- **Traffic Evaluation:** Tests detection behavior against synthetic packet captures and controlled localhost traffic.

## Technologies Used

- Python
- Scapy
- Wireshark
- Streamlit
- Pandas
- JSON
- Git

## How It Works

1. A PCAP file containing network packets is supplied to the application.
2. Scapy extracts relevant packet information.
3. Three independent detection modules analyze the traffic.
4. Activity matching configured detection thresholds generates alerts.
5. Alerts are displayed in the terminal and saved as JSON reports.
6. Streamlit displays the saved results in an interactive dashboard.

## Installation

Clone the repository:

```bash
git clone https://github.com/SanathT89/network-intrusion-detection-system.git
cd network-intrusion-detection-system
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it in Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Running the IDS

Analyze a packet capture:

```bash
python run_ids.py captures/scan_test.pcap
```

Other examples:

```bash
python run_ids.py captures/icmp_spike.pcap
python run_ids.py captures/tcp_spike.pcap
```

## Running the Dashboard

```bash
python -m streamlit run dashboard/app.py
```

Open `http://localhost:8501` in your browser.

## Running Tests

```bash
python -m tests.test_all
python -m tests.test_icmp
python -m tests.test_connections
python -m tests.test_logging
```

## Detection Evaluation

The detection modules were evaluated using controlled synthetic PCAP datasets and locally generated TCP traffic.

| Test Scenario | Expected Outcome | Actual Outcome |
|---|---|---|
| Rapid TCP port scan | Alert | Alert triggered |
| Slow TCP port scan | May evade detection | No alert detected |
| ICMP request spike | Alert | Alert triggered |
| Excessive TCP connections | Alert | Alert triggered |
| Normal TCP traffic | No alert | No alert triggered |
| Legitimate repeated HTTP connections | May trigger a false positive | Alert triggered - flase positive |

The evaluation uses experimental thresholds and a limited dataset. The findings should not be interpreted as production level intrusion detection accuracy.

## Limitations

- Detects predefined traffic patterns rather than confirming malicious activity.
- Does not perform application layer payload inspection.
- Slowly distributed scans may evade short detection windows.
- Legitimate activity may trigger threshold based alerts.
- TCP SYN retransmissions may affect counts.
- Currently operates on saved PCAP files rather than continuous live traffic.
- Testing is primarily based on controlled synthetic traffic.

## Future Improvements

- Real time packet monitoring.
- More advanced traffic correlation.
- Detection of additional network attack patterns.
- Evaluation on larger, labeled datasets.
- Comparison against established intrusion detection systems such as Suricata.

## Project Purpose

This project was developed as a practical exploration of network security, protocol analysis, detection engineering, and the challenges of distinguishing suspicious from legitimate network activity.