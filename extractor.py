"""IOC extraction and normalization module."""
from __future__ import annotations
import ipaddress
import re
from typing import Dict, List

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

def is_public_ipv4(value: str) -> bool:
    """Return True only for globally routable IPv4 candidates."""
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4 and ip.is_global
    except ValueError:
        return False

def extract_ips(text: str) -> List[str]:
    return sorted({ip for ip in IPV4_PATTERN.findall(text) if is_public_ipv4(ip)})

def extract_domains(text: str) -> List[str]:
    results = set()
    for domain in DOMAIN_PATTERN.findall(text):
        domain = domain.lower().rstrip(".")
        if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", domain):
            results.add(domain)
    return sorted(results)

def extract_md5(text: str) -> List[str]:
    return sorted({value.lower() for value in MD5_PATTERN.findall(text)})

def extract_sha256(text: str) -> List[str]:
    return sorted({value.lower() for value in SHA256_PATTERN.findall(text)})

def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract all supported IOC types."""
    return {
        "ip": extract_ips(text),
        "domain": extract_domains(text),
        "md5": extract_md5(text),
        "sha256": extract_sha256(text),
    }

def flatten_iocs(iocs: Dict[str, List[str]]) -> List[Dict[str, str]]:
    """Convert grouped IOCs into a flat list."""
    return [
        {"ioc": value, "type": ioc_type}
        for ioc_type, values in iocs.items()
        for value in values
    ]

def read_log_file(file_path: str) -> str:
    """Read a text log safely."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as file:
        return file.read()
