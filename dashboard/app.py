
import json
from pathlib import Path
import pandas as pd
import streamlit as st


st.set_page_config(
    page_title="Network IDS Dashboard",
    layout="wide"
)
st.markdown("**Network Intrusion Detection System**")
st.caption("Security Alert Monitoring and Traffic Analysis")
st.divider()

BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "logs"

def load_alerts():
    all_alerts = []
    loaded_files = []
    errors = []

    for file_path in sorted(LOGS_DIR.glob("*_alerts.json")):
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                report = json.load(file)

            if not isinstance(report.get("alerts"), list):
                raise ValueError("Missing or invalid alerts list")

            loaded_files.append(file_path.name)

            for alert in report["alerts"]:
                all_alerts.append({
                    "type": alert.get("type", "Unknown"),
                    "source": alert.get("source", "Unknown"),
                    "destination": alert.get("destination", "Unknown"),
                    "detected_at": alert.get("detected_at"),
                    "capture_file": report.get(
                        "capture_file", file_path.name
                    )
                })

        except (OSError, ValueError, TypeError) as error:
            errors.append(f"{file_path.name}: {error}")

    return all_alerts, loaded_files, errors


alerts, loaded_files, errors = load_alerts()

for error in errors:
    st.warning(f"Could not load {error}")


st.markdown("**Dashboard Overview**")

total_alerts = len(alerts)
total_captures = len(loaded_files)
alert_types = len({alert["type"] for alert in alerts})

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("PCAP Reports", total_captures)

with col2:
    st.metric("Total Alerts", total_alerts)

with col3:
    st.metric("Detection Types", alert_types)

st.divider()

if total_alerts == 0:
    st.info("No security alerts found.")

    if loaded_files:
        st.success(
            f"Loaded {total_captures} reports with zero alerts."
        )
    else:
        st.warning(
            "Run your IDS to generate JSON reports."
        )

    st.stop()


df = pd.DataFrame(alerts)

df["detected_time"] = pd.to_datetime(
    df["detected_at"],
    unit="s",
    utc=True,
    errors="coerce"
)

st.sidebar.markdown("**Detection Filters**")

available_types = sorted(df["type"].unique())

selected_type = st.sidebar.selectbox(
    "Detection Type",
    ["All Types"] + available_types
)

if selected_type == "All Types":
    filtered_df = df.copy()
else:
    filtered_df = df[
        df["type"] == selected_type
    ].copy()

st.sidebar.caption(
    "Select a detection type to filter the dashboard."
)

st.markdown("**Alerts by Detection Type**")

type_counts = (
    filtered_df["type"]
    .value_counts()
    .rename_axis("Detection Type")
    .reset_index(name="Alerts")
)

st.bar_chart(
    type_counts,
    x="Detection Type",
    y="Alerts"
)

st.divider()

st.markdown("**Most Frequent Alert Sources**")

source_counts = (
    filtered_df["source"]
    .value_counts()
    .head(10)
    .rename_axis("Source IP")
    .reset_index(name="Alerts")
)

st.bar_chart(
    source_counts,
    x="Source IP",
    y="Alerts"
)

st.divider()

st.markdown("**Security Alert Timeline**")

timeline_df = filtered_df.dropna(
    subset=["detected_time"]
).copy()

if not timeline_df.empty:

    timeline_df["minute"] = (
        timeline_df["detected_time"].dt.floor("min")
    )

    timeline = (
        timeline_df
        .groupby("minute")
        .size()
        .reset_index(name="Alerts")
        .sort_values("minute")
    )

    st.line_chart(
        timeline,
        x="minute",
        y="Alerts"
    )

else:
    st.info("No valid timestamps available.")

st.caption(
    "Timeline timestamps originate from captured packets, "
    "including simulated traffic."
)

st.divider()

st.markdown("**Security Alert Details**")

display_columns = [
    "detected_time",
    "type",
    "source",
    "destination",
    "capture_file"
]

display_df = filtered_df[
    display_columns
].sort_values(
    "detected_time",
    ascending=False
)

st.dataframe(
    display_df,
    hide_index=True,
    use_container_width=True
)

st.divider()

st.markdown("**Export Security Reports**")

csv_data = display_df.to_csv(index=False)

st.download_button(
    label="Download Alerts as CSV",
    data=csv_data,
    file_name="nids_alerts.csv",
    mime="text/csv"
)

st.divider()

st.caption(
    "Network Intrusion Detection System | "
    "Python + Scapy + Streamlit"
)

st.caption(
    "Educational prototype: Alerts represent suspicious "
    "traffic patterns, not confirmed cyberattacks."
)
