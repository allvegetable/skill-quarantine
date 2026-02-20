"""Prompt injection detection rules for text content."""

from __future__ import annotations

import re
from typing import Dict, List

RULES = [
    (r"ignore previous instructions|disregard|you are now|forget your rules", "Instruction override phrase"),
    (r"print env|output your system prompt|show api key|echo \$openai", "Sensitive data output request"),
    (r"\[system message\]|<system>|\[inst\]", "System message impersonation"),
    (r"do not tell the user|silently|without mentioning", "Concealment directive"),
    (
        r"\b(send|post|upload)\s+to\b.*(https?://[^\s'\"`]+|(?:\d{1,3}\.){3}\d{1,3}\b)",
        "Potential exfiltration instruction",
    ),
]


def scan(file_path: str, content: str) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        for pattern, label in RULES:
            if re.search(pattern, line, flags=re.IGNORECASE):
                findings.append(
                    {
                        "rule": "prompt_injection",
                        "category": "prompt_injection",
                        "severity": "CRITICAL",
                        "file": file_path,
                        "line": line_no,
                        "message": f"{label} detected",
                        "evidence": line.strip(),
                    }
                )
    return findings
