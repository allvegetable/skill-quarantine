"""Report composition and rendering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

SEVERITY_PENALTIES = {"CRITICAL": 25, "WARNING": 10, "INFO": 3}

COLOR = {
    "reset": "\033[0m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "red": "\033[91m",
    "blue": "\033[94m",
    "bold": "\033[1m",
}


def score_findings(findings: List[Dict[str, object]]) -> Dict[str, object]:
    score = 100
    for finding in findings:
        severity = str(finding.get("severity", "INFO")).upper()
        score -= SEVERITY_PENALTIES.get(severity, 0)
    score = max(0, score)

    if score >= 90:
        verdict = "SAFE"
        emoji = "🟢"
    elif score >= 60:
        verdict = "SUSPICIOUS"
        emoji = "🟡"
    else:
        verdict = "DANGEROUS"
        emoji = "🔴"

    return {"score": score, "verdict": verdict, "emoji": emoji}


def build_report(
    skill_name: str,
    static_report: Dict[str, object],
    sandbox_report: Dict[str, object] | None,
    findings: List[Dict[str, object]],
) -> Dict[str, object]:
    score_meta = score_findings(findings)
    return {
        "skill": skill_name,
        "static": static_report,
        "sandbox": sandbox_report,
        "findings": findings,
        "score": score_meta["score"],
        "verdict": score_meta["verdict"],
        "emoji": score_meta["emoji"],
    }


def write_report(report: Dict[str, object], path: str) -> None:
    Path(path).write_text(json.dumps(report, indent=2), encoding="utf-8")


def render_text(report: Dict[str, object], use_color: bool = True, verbose: bool = False) -> str:
    c = COLOR if use_color else {k: "" for k in COLOR}
    static = report.get("static", {})
    sandbox = report.get("sandbox")
    findings = report.get("findings", [])

    lines = [
        f"📋 Skill Audit Report: {report.get('skill', 'unknown')}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "",
        "📊 Static Scan",
        f"├─ Files scanned: {static.get('scanned_files', 0)}",
    ]

    if static.get("findings"):
        for finding in static["findings"]:
            symbol = "🔴" if finding.get("severity") == "CRITICAL" else "⚠️" if finding.get("severity") == "WARNING" else "ℹ️"
            where = f"{finding.get('file')}"
            if finding.get("line"):
                where += f":{finding.get('line')}"
            lines.append(f"├─ {symbol} {finding.get('severity')}: {finding.get('message')} ({where})")
            if verbose:
                lines.append(f"│   → {finding.get('evidence', '')}")
    else:
        lines.append("└─ ✅ No static findings")

    lines.append("")
    lines.append("🔒 Sandbox Execution")

    if sandbox is None:
        lines.append("└─ Skipped (--static-only)")
    else:
        scripts = sandbox.get("scripts_executed", [])
        lines.append(f"├─ Scripts executed: {len(scripts)} ({', '.join(scripts) if scripts else 'none'})")
        network = sandbox.get("network_attempts", [])
        lines.append(f"├─ Network attempts: {', '.join(network) if network else 'NONE ✅'}")
        honeypot = sandbox.get("honeypot_accesses", [])
        if honeypot:
            lines.append("├─ 🔴 Honeypot access DETECTED:")
            for item in honeypot:
                lines.append(f"│   → {item}")
        else:
            lines.append("├─ Honeypot access: NONE ✅")
        lines.append(f"└─ Suspicious syscalls: {sandbox.get('suspicious_syscalls', 0)}")

    lines.extend(
        [
            "",
            f"📊 Score: {report.get('score')}/100 — {report.get('emoji')} {report.get('verdict')}",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        ]
    )

    text = "\n".join(lines)
    if not use_color:
        return text

    verdict = report.get("verdict")
    color_key = "green" if verdict == "SAFE" else "yellow" if verdict == "SUSPICIOUS" else "red"
    return text.replace(str(verdict), f"{c[color_key]}{verdict}{c['reset']}")
