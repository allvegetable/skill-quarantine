"""Network exfiltration detection rules."""

from __future__ import annotations

import re
from typing import Dict, List

KNOWN_EXFIL = ["pastebin", "requestbin", "webhook.site", "ngrok"]
NETWORK_PATTERNS = [
    r"\bcurl\b|\bwget\b|fetch\(|requests\.post|http\.request|socket\.(connect|create_connection|sendto|send|sendall|sendmsg|connect_ex)\b",
    r"dns\.|nslookup|dig\s+",
]
LOCAL_ALLOW = re.compile(r"localhost|127\.0\.0\.1|::1")
URL_PATTERN = re.compile(r"https?://([^\s'\"`]+)", re.IGNORECASE)


def scan(file_path: str, content: str) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        if not any(re.search(pattern, line, flags=re.IGNORECASE) for pattern in NETWORK_PATTERNS):
            continue

        severity = "WARNING"
        message = "Network-capable operation detected"
        urls = URL_PATTERN.findall(line)
        for host in urls:
            if any(token in host.lower() for token in KNOWN_EXFIL):
                severity = "CRITICAL"
                message = f"Known exfiltration endpoint referenced: {host}"
                break
            if not LOCAL_ALLOW.search(host):
                severity = "CRITICAL"
                message = f"Outbound network target detected: {host}"

        findings.append(
            {
                "rule": "network",
                "category": "network",
                "severity": severity,
                "file": file_path,
                "line": line_no,
                "message": message,
                "evidence": line.strip(),
            }
        )
    return findings
