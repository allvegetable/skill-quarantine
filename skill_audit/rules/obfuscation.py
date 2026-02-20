"""Obfuscation detection rules."""

from __future__ import annotations

import re
from typing import Dict, List

ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\ufeff"}


def scan(file_path: str, content: str) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    lines = content.splitlines()

    for line_no, line in enumerate(lines, start=1):
        lowered = line.lower()
        if "base64" in lowered and ("eval(" in lowered or "exec(" in lowered):
            findings.append(
                {
                    "rule": "obfuscation",
                    "category": "obfuscation",
                    "severity": "WARNING",
                    "file": file_path,
                    "line": line_no,
                    "message": "base64 decode paired with eval/exec",
                    "evidence": line.strip(),
                }
            )

        if ("eval(" in lowered or "exec(" in lowered) and ("+" in line or "join(" in lowered):
            findings.append(
                {
                    "rule": "obfuscation",
                    "category": "obfuscation",
                    "severity": "WARNING",
                    "file": file_path,
                    "line": line_no,
                    "message": "Dynamic string construction with eval/exec",
                    "evidence": line.strip(),
                }
            )

        if len(line) > 500:
            findings.append(
                {
                    "rule": "obfuscation",
                    "category": "obfuscation",
                    "severity": "INFO",
                    "file": file_path,
                    "line": line_no,
                    "message": "Very long single line (>500 chars)",
                    "evidence": line[:160].strip(),
                }
            )

        if any(char in line for char in ZERO_WIDTH):
            findings.append(
                {
                    "rule": "obfuscation",
                    "category": "obfuscation",
                    "severity": "WARNING",
                    "file": file_path,
                    "line": line_no,
                    "message": "Zero-width character detected",
                    "evidence": line.strip(),
                }
            )

        if re.search(r"\\x[0-9a-fA-F]{2}|\\[0-7]{3}", line):
            findings.append(
                {
                    "rule": "obfuscation",
                    "category": "obfuscation",
                    "severity": "INFO",
                    "file": file_path,
                    "line": line_no,
                    "message": "Hex/octal encoded string literal",
                    "evidence": line.strip(),
                }
            )

        if "string.fromcharcode" in lowered or re.search(r"chr\(.+\)\s*\+\s*chr\(", lowered):
            findings.append(
                {
                    "rule": "obfuscation",
                    "category": "obfuscation",
                    "severity": "WARNING",
                    "file": file_path,
                    "line": line_no,
                    "message": "Character code assembly detected",
                    "evidence": line.strip(),
                }
            )

    return findings
