"""Threat Intelligence enrichment engine for VirusTotal and AbuseIPDB."""
from __future__ import annotations
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
CACHE_FILE = os.getenv("CACHE_FILE", "data/cache/ti_cache.json")
CACHE_TTL_HOURS = float(os.getenv("CACHE_TTL_HOURS", "24"))
REQUEST_TIMEOUT = 15

class IOCache:
    """Simple JSON cache with TTL."""
    def __init__(self, cache_file: str = CACHE_FILE):
        self.cache_file = Path(cache_file)
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self.data = self._load()

    def _load(self) -> Dict[str, Any]:
        if not self.cache_file.exists():
            return {}
        try:
            with open(self.cache_file, "r", encoding="utf-8") as file:
                return json.load(file)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self) -> None:
        temporary_file = self.cache_file.with_suffix(".tmp")
        with open(temporary_file, "w", encoding="utf-8") as file:
            json.dump(self.data, file, indent=2)
        temporary_file.replace(self.cache_file)

    @staticmethod
    def _key(ioc_type: str, ioc: str) -> str:
        return hashlib.sha256(f"{ioc_type}:{ioc.lower()}".encode()).hexdigest()

    def get(self, ioc_type: str, ioc: str) -> Optional[Dict[str, Any]]:
        entry = self.data.get(self._key(ioc_type, ioc))
        if not entry:
            return None
        if time.time() - entry.get("timestamp", 0) > CACHE_TTL_HOURS * 3600:
            return None
        return entry.get("data")

    def set(self, ioc_type: str, ioc: str, value: Dict[str, Any]) -> None:
        self.data[self._key(ioc_type, ioc)] = {
            "timestamp": time.time(),
            "data": value,
        }
        self._save()

def _handle_response(response: requests.Response) -> Dict[str, Any]:
    if response.status_code == 200:
        return response.json()
    if response.status_code == 404:
        return {"error": "IOC not found"}
    if response.status_code == 401:
        return {"error": "Invalid or unauthorized API key"}
    if response.status_code == 403:
        return {"error": "API access forbidden"}
    if response.status_code == 429:
        return {"error": "API rate limit exceeded"}
    return {"error": f"API request failed with HTTP {response.status_code}"}

class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def lookup(self, ioc_type: str, ioc: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        if ioc_type == "ip":
            endpoint = f"ip_addresses/{ioc}"
        elif ioc_type == "domain":
            endpoint = f"domains/{ioc}"
        elif ioc_type in ("md5", "sha256"):
            endpoint = f"files/{ioc}"
        else:
            return {"error": f"Unsupported IOC type: {ioc_type}"}
        try:
            response = requests.get(
                f"{self.BASE_URL}/{endpoint}",
                headers={"x-apikey": self.api_key, "Accept": "application/json"},
                timeout=REQUEST_TIMEOUT,
            )
            return _handle_response(response)
        except requests.Timeout:
            return {"error": "VirusTotal request timed out"}
        except requests.RequestException as exc:
            return {"error": f"VirusTotal network error: {exc}"}

class AbuseIPDBClient:
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}
        try:
            response = requests.get(
                self.BASE_URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=REQUEST_TIMEOUT,
            )
            return _handle_response(response)
        except requests.Timeout:
            return {"error": "AbuseIPDB request timed out"}
        except requests.RequestException as exc:
            return {"error": f"AbuseIPDB network error: {exc}"}

class ThreatIntelEngine:
    def __init__(self, vt_api_key: str = VT_API_KEY, abuse_api_key: str = ABUSEIPDB_API_KEY):
        self.cache = IOCache()
        self.vt = VirusTotalClient(vt_api_key)
        self.abuse = AbuseIPDBClient(abuse_api_key)

    def enrich(self, ioc_type: str, ioc: str) -> Dict[str, Any]:
        cached = self.cache.get(ioc_type, ioc)
        if cached is not None:
            cached = dict(cached)
            cached["cached"] = True
            return cached

        result = {
            "ioc": ioc,
            "type": ioc_type,
            "cached": False,
            "virustotal": self.vt.lookup(ioc_type, ioc),
            "abuseipdb": None,
        }

        result["abuseipdb"] = (
            self.abuse.lookup_ip(ioc)
            if ioc_type == "ip"
            else {
                "status": "not_applicable",
                "message": "AbuseIPDB enrichment is IP-focused",
            }
        )
        self.cache.set(ioc_type, ioc, result)
        return result
