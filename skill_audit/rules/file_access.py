"""Sensitive file access detection rules."""

from __future__ import annotations

import re
from typing import Dict, List

PATTERNS = [
    r"~/.ssh/|/etc/ssh/|id_rsa|known_hosts",
    r"~/.aws/|aws_access_key_id|aws_secret_access_key|credentials",
    r"~/.openclaw/|~/.config/openclaw/|openclaw/config.json",
    r"\.env|secrets?",
    r"~/.mozilla|~/.config/google-chrome|cookies|localstorage",
]
TOKEN_PASSWORD_PATTERN = re.compile(r"\b(token|password)\b", flags=re.IGNORECASE)
PATH_CALL_PATTERN = re.compile(r"\b(open|read_text|Path)\s*\(")
PATH_HINT_PATTERN = re.compile(r"[~/]|[A-Za-z]:\\")


def scan(file_path: str, content: str) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        lowered = line.lower()
        if TOKEN_PASSWORD_PATTERN.search(line) and (
            PATH_CALL_PATTERN.search(line) or PATH_HINT_PATTERN.search(line)
        ):
            findings.append(
                {
                    "rule": "file_access",
                    "category": "file_access",
                    "severity": "CRITICAL",
                    "file": file_path,
                    "line": line_no,
                    "message": "Sensitive file access pattern detected",
                    "evidence": line.strip(),
                }
            )
            continue

        for pattern in PATTERNS:
            if re.search(pattern, lowered, flags=re.IGNORECASE):
                findings.append(
                    {
                        "rule": "file_access",
                        "category": "file_access",
                        "severity": "CRITICAL",
                        "file": file_path,
                        "line": line_no,
                        "message": "Sensitive file access pattern detected",
                        "evidence": line.strip(),
                    }
                )
                break
    return findings
