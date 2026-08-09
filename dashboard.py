import os
import time
import pandas as pd
import streamlit as st

# Page Configuration
st.set_page_config(
    page_title="SOAR Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# Title & Header
st.title("🛡️ Automated SOAR Engine & Threat Intel Dashboard")
st.markdown(
    "Real-time monitoring of Honeypot Telemetry, Threat Intelligence, and Automated Mitigation Actions."
)

DENYLIST_FILE = "./denylist.txt"
LOG_FILE = "./logs/cowrie.json"

# Auto Refresh Control (Every 3 seconds refresh)
st.sidebar.header("Dashboard Controls")
auto_refresh = st.sidebar.checkbox("Auto Refresh Data", value=True)
if auto_refresh:
    time.sleep(3)
    st.rerun()

# --- TOP METRIC CARDS ---
col1, col2, col3 = st.columns(3)

# Calculate Denylist Count
blocked_count = 0
if os.path.exists(DENYLIST_FILE):
    with open(DENYLIST_FILE, "r") as f:
        blocked_count = len(f.readlines())

col1.metric(
    label="⛔ Total Blocked Malicious IPs",
    value=blocked_count,
    delta="Active Action",
)
col2.metric(label="🚨 Threat Severity Threshold", value="CRITICAL (>= 80%)")
col3.metric(label="⚙️ Engine Status", value="ACTIVE (Listening)")

st.divider()

# --- SECTION 1: BLOCKED IPS LOG (DENYLIST) ---
st.subheader("🚫 Automatically Blocked IPs (Denylist)")

if os.path.exists(DENYLIST_FILE) and blocked_count > 0:
    with open(DENYLIST_FILE, "r") as f:
        lines = f.readlines()

    # Parse denylist text lines to DataFrame
    data = []
    for line in lines:
        if " - BLOCKED IP: " in line:
            parts = line.strip().split(" - BLOCKED IP: ")
            timestamp = parts[0]
            ip_info = parts[1].split(" | Risk: ")
            ip = ip_info[0]
            risk = ip_info[1] if len(ip_info) > 1 else "CRITICAL"
            data.append(
                {"Timestamp": timestamp, "Blocked IP": ip, "Risk Severity": risk}
            )

    df_blocked = pd.DataFrame(data)
    st.dataframe(df_blocked, use_container_width=True)
else:
    st.info("No IPs blocked yet. Waiting for Critical threat detections.")

st.divider()

# --- SECTION 2: LIVE TELEMETRY LOGS ---
st.subheader("📊 Honeypot Log File Status")
if os.path.exists(LOG_FILE):
    st.success(f"Log File Path Identified: `{LOG_FILE}`")
    file_size = os.path.getsize(LOG_FILE) / 1024
    st.caption(f"Current Log File Size: {file_size:.2f} KB")
else:
    st.warning("Honeypot Log file not found. Ensure Cowrie is running.")