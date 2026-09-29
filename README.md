# Automated Threat Intelligence & Log Enrichment Pipeline

Python/Streamlit SOC triage application for extracting IPs, domains and hashes from logs, enriching them with VirusTotal and AbuseIPDB, scoring risk, and exporting CSV/JSON reports.

## Requirements
- Python 3.10+
- VirusTotal API key
- AbuseIPDB API key

## Installation

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and add your API keys.

Run:

```powershell
streamlit run app.py
```

## Features
- Public IPv4 extraction with private/internal IP filtering
- Domain, MD5 and SHA-256 extraction
- VirusTotal API v3 enrichment
- AbuseIPDB API v2 IP enrichment
- JSON cache with configurable TTL
- Low/Medium/High/Critical risk classification
- SOC triage recommendations
- Manual IOC lookup
- `.log`, `.txt`, `.csv` uploads
- CSV and JSON report downloads

## Risk model
AbuseIPDB:
- 90+: +50
- 75-89: +40
- 50-74: +25
- 25-49: +10

VirusTotal malicious engines:
- 10+: +50
- 5-9: +40
- 3-4: +30
- 1-2: +20

Suspicious engines add +3 each, capped at +10.

Classification:
- 0-24 Low
- 25-49 Medium
- 50-74 High
- 75-100 Critical

Do not commit `.env` or API keys to source control.
