"""Static scanner for skill packages."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Dict, Iterable, List

from skill_audit.rules import file_access, network, obfuscation, privilege, prompt_injection

Finding = Dict[str, object]

TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".py",
    ".sh",
    ".js",
    ".ts",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
}

SCRIPT_EXTENSIONS = {".py", ".sh", ".js", ".ts", ".bash", ".zsh"}


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="latin-1")
        except UnicodeDecodeError:
            return None


def _iter_files(base: Path) -> Iterable[Path]:
    for path in base.rglob("*"):
        rel_parts = path.relative_to(base).parts
        if path.is_file() and not any(part.startswith(".") for part in rel_parts):
            yield path


def scan_skill(skill_path: str) -> Dict[str, object]:
    base = Path(skill_path).resolve()
    if not base.is_dir():
        raise FileNotFoundError(f"Skill path does not exist or is not a directory: {skill_path}")

    findings: List[Finding] = []
    scanned_files = 0

    for file_path in _iter_files(base):
        suffix = file_path.suffix.lower()
        if suffix not in TEXT_EXTENSIONS:
            continue

        content = _read_text(file_path)
        if content is None:
            continue

        rel_file = str(file_path.relative_to(base))
        scanned_files += 1

        if suffix in TEXT_EXTENSIONS:
            findings.extend(prompt_injection.scan(rel_file, content))

        if suffix in SCRIPT_EXTENSIONS:
            for rule in (file_access.scan, network.scan, obfuscation.scan, privilege.scan):
                findings.extend(rule(rel_file, content))

    return {
        "skill_path": str(base),
        "scanned_files": scanned_files,
        "findings": findings,
        "counts": _count_by_severity(findings),
    }


def _count_by_severity(findings: List[Finding]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
    for finding in findings:
        severity = str(finding.get("severity", "INFO")).upper()
        counts[severity] = counts.get(severity, 0) + 1
    return counts
