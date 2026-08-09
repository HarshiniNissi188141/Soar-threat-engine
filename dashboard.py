import streamlit as st
import pandas as pd
import json
import os

st.set_page_config(page_title="SOC Command Center", layout="wide")

st.title("🛡️ Enterprise SOAR Platform & Incident Lifecycle Dashboard")

# Top Metrics Row
col1, col2, col3 = st.columns(3)

audit_trail = []
if os.path.exists("./audit_trail.json"):
    with open("./audit_trail.json", "r") as f:
        try:
            audit_trail = json.load(f)
        except:
            audit_trail = []

total_incidents = len(audit_trail)
contained_incidents = sum(1 for x in audit_trail if x.get("status") == "CONTAINED")

col1.metric("Total Processed Incidents", total_incidents)
col2.metric("Auto-Contained Threats", contained_incidents)
col3.metric("SOAR Engine Status", "ACTIVE (Multi-Vector)", delta="Operational")

st.markdown("---")

# Incident Audit & Playbook View
st.subheader("📋 Incident Audit Trail & Playbook Executions")

if audit_trail:
    df_audit = pd.DataFrame(audit_trail)
    st.dataframe(df_audit[["incident_id", "timestamp", "target_ip", "playbook", "status"]], use_container_width=True)
    
    st.subheader("🔎 Deep-Dive Incident Audit & Rollback Options")
    selected_inc = st.selectbox("Select Incident ID to Inspect", df_audit["incident_id"].unique())
    
    inc_details = next(item for item in audit_trail if item["incident_id"] == selected_inc)
    
    st.write(f"**Playbook Used:** `{inc_details['playbook']}`")
    st.write(f"**Rollback Command:** `{inc_details['rollback_command']}`")
    
    st.markdown("##### Playbook Steps Executed:")
    st.json(inc_details["lifecycle"])
else:
    st.info("No audit trail entries found. Run `python soar_engine.py` to trigger incidents.")