"""Privilege escalation rule checks."""

from __future__ import annotations

import re
from typing import Dict, List

RULES = [
    (r"\bsudo\b|\bsu\b|\bdoas\b", "WARNING", "Privilege escalation command"),
    (r"chmod\s+777|chmod\s+\+s", "CRITICAL", "Dangerous permission change"),
    (r"chown\s+root", "WARNING", "Root ownership change"),
    (r"\b(kill|pkill)\b.*(openclaw|docker)", "WARNING", "Service/process disruption"),
    (r"\bcrontab\b|/etc/cron", "WARNING", "Cron persistence attempt"),
    (r"systemctl\s+|/etc/systemd/system", "WARNING", "Systemd service manipulation"),
]


def scan(file_path: str, content: str) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        for pattern, severity, message in RULES:
            if re.search(pattern, line, flags=re.IGNORECASE):
                findings.append(
                    {
                        "rule": "privilege",
                        "category": "privilege",
                        "severity": severity,
                        "file": file_path,
                        "line": line_no,
                        "message": message,
                        "evidence": line.strip(),
                    }
                )
                break
    return findings
