"""Streamlit SOC Threat Intelligence Dashboard."""
from __future__ import annotations
import io
import json
import os

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from extractor import extract_iocs, flatten_iocs
from enricher import ThreatIntelEngine
from scorer import calculate_risk

load_dotenv()

st.set_page_config(
    page_title="SOC Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Automated Threat Intelligence & Log Enrichment")
st.caption("IOC extraction → Threat Intelligence enrichment → Risk scoring → SOC triage")

st.sidebar.header("Threat Intelligence Configuration")
vt_api_key = st.sidebar.text_input(
    "VirusTotal API Key",
    value=os.getenv("VT_API_KEY", ""),
    type="password",
)
abuse_api_key = st.sidebar.text_input(
    "AbuseIPDB API Key",
    value=os.getenv("ABUSEIPDB_API_KEY", ""),
    type="password",
)
st.sidebar.divider()
st.sidebar.info("Keys entered here are used for the current Streamlit session.")

engine = ThreatIntelEngine(vt_api_key=vt_api_key, abuse_api_key=abuse_api_key)

if "results" not in st.session_state:
    st.session_state.results = []

st.subheader("Manual IOC Lookup")
manual_ioc = st.text_input("Enter an IP address, domain, MD5 or SHA-256 hash")

if st.button("Analyze IOC", type="primary"):
    if not manual_ioc.strip():
        st.warning("Please enter an IOC.")
    else:
        extracted = extract_iocs(manual_ioc.strip().lower())
        flat = flatten_iocs(extracted)
        if not flat:
            st.error("The supplied value could not be identified as a supported IOC.")
        else:
            item = flat[0]
            with st.spinner("Querying threat intelligence providers..."):
                enrichment = engine.enrich(item["type"], item["ioc"])
                risk = calculate_risk(enrichment)
            st.session_state.results = [{
                **item, **risk,
                "virustotal": enrichment.get("virustotal"),
                "abuseipdb": enrichment.get("abuseipdb"),
            }]
            st.success(f"Analysis complete: {risk['severity']}")

st.subheader("Log File Analysis")
uploaded_file = st.file_uploader(
    "Upload a .log, .txt or .csv file",
    type=["log", "txt", "csv"],
)

def read_uploaded_file(file) -> str:
    raw = file.getvalue()
    if file.name.lower().endswith(".csv"):
        try:
            return pd.read_csv(io.BytesIO(raw)).to_csv(index=False)
        except Exception:
            pass
    return raw.decode("utf-8", errors="replace")

if uploaded_file is not None and st.button("Analyze Uploaded File", type="primary"):
    text = read_uploaded_file(uploaded_file)
    flat_iocs = flatten_iocs(extract_iocs(text))

    if not flat_iocs:
        st.warning("No supported public IP addresses, domains or file hashes were detected.")
    else:
        results = []
        progress = st.progress(0)
        for index, item in enumerate(flat_iocs, start=1):
            enrichment = engine.enrich(item["type"], item["ioc"])
            risk = calculate_risk(enrichment)
            results.append({
                **item, **risk,
                "virustotal": enrichment.get("virustotal"),
                "abuseipdb": enrichment.get("abuseipdb"),
            })
            progress.progress(index / len(flat_iocs))
        st.session_state.results = results
        st.success(f"Processed {len(results)} unique IOCs.")

results = st.session_state.results

if results:
    dataframe = pd.DataFrame(results)
    total_iocs = len(dataframe)
    high_critical = len(dataframe[dataframe["severity"].isin(["High", "Critical"])])
    critical = len(dataframe[dataframe["severity"] == "Critical"])

    col1, col2, col3 = st.columns(3)
    col1.metric("Total IOCs", total_iocs)
    col2.metric("High / Critical", high_critical)
    col3.metric("Critical", critical)

    st.subheader("SOC Triage Results")
    display_columns = [
        "ioc", "type", "severity", "risk_score",
        "geolocation", "abuse_score", "vt_ratio", "recommendation",
    ]
    st.dataframe(dataframe[display_columns], use_container_width=True, hide_index=True)

    st.subheader("Severity Distribution")
    counts = dataframe["severity"].value_counts().rename_axis("Severity").reset_index(name="Count")
    st.bar_chart(counts.set_index("Severity"))

    st.download_button(
        "⬇️ Download JSON Report",
        data=json.dumps(results, indent=2, default=str),
        file_name="threat_intelligence_report.json",
        mime="application/json",
    )

    csv_dataframe = dataframe.copy()
    for column in ["virustotal", "abuseipdb"]:
        csv_dataframe[column] = csv_dataframe[column].apply(lambda value: json.dumps(value, default=str))

    st.download_button(
        "⬇️ Download CSV Report",
        data=csv_dataframe.to_csv(index=False),
        file_name="threat_intelligence_report.csv",
        mime="text/csv",
    )

st.divider()
st.caption(
    "Threat intelligence results are contextual indicators, not definitive proof "
    "of malicious activity. Correlate with internal security telemetry."
)
