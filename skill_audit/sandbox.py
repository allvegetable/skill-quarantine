"""Docker sandbox execution and behavior analysis."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List

from skill_audit.honeypot import create_honeypot


class SandboxError(RuntimeError):
    """Raised when sandbox execution fails."""


def run_sandbox(
    skill_dir: str,
    image_tag: str = "skill-quarantine:latest",
    docker_context: str | None = None,
    timeout_seconds: int = 120,
) -> Dict[str, object]:
    skill_path = Path(skill_dir).resolve()
    if not skill_path.is_dir():
        raise SandboxError(f"Skill directory does not exist: {skill_dir}")

    docker_context_path = Path(docker_context) if docker_context else Path(__file__).resolve().parents[1] / "docker"
    if not docker_context_path.exists():
        raise SandboxError(f"Docker context not found: {docker_context_path}")

    _ensure_docker_image(image_tag, docker_context_path)

    with tempfile.TemporaryDirectory(prefix="skill-audit-") as temp_dir:
        temp = Path(temp_dir)
        honeypot_dir = temp / "honeypot"
        results_dir = temp / "results"
        honeypot_dir.mkdir(parents=True, exist_ok=True)
        results_dir.mkdir(parents=True, exist_ok=True)

        honeypot = create_honeypot(str(honeypot_dir))

        cmd = [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "-v",
            f"{skill_path}:/audit/skill:ro",
            "-v",
            f"{honeypot_dir}:/home/auditor",
            "-v",
            f"{results_dir}:/audit/results",
            image_tag,
        ]

        try:
            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise SandboxError(f"Sandbox timed out after {timeout_seconds}s") from exc

        analysis = analyze_results(str(results_dir), honeypot)
        analysis["docker_stdout"] = proc.stdout
        analysis["docker_stderr"] = proc.stderr
        analysis["returncode"] = proc.returncode
        analysis["honeypot"] = honeypot
        return analysis


def _ensure_docker_image(image_tag: str, docker_context_path: Path) -> None:
    if shutil.which("docker") is None:
        raise SandboxError("Docker executable not found in PATH")

    inspect = subprocess.run(
        ["docker", "image", "inspect", image_tag],
        check=False,
        capture_output=True,
        text=True,
    )
    if inspect.returncode == 0:
        return

    build = subprocess.run(
        ["docker", "build", "-t", image_tag, str(docker_context_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        raise SandboxError(f"Failed to build Docker image: {build.stderr.strip()}")


def analyze_results(results_dir: str, honeypot_meta: Dict[str, object]) -> Dict[str, object]:
    results_path = Path(results_dir)
    if not results_path.exists():
        raise SandboxError(f"Sandbox results directory missing: {results_dir}")

    files_accessed: List[str] = []
    network_attempts: List[str] = []
    execs: List[str] = []

    for strace_file in sorted(results_path.glob("*.strace*")):
        data = strace_file.read_text(encoding="utf-8", errors="replace")
        files_accessed.extend(_parse_open_paths(data))
        network_attempts.extend(_parse_connect_calls(data))
        execs.extend(_parse_execve_calls(data))

    honeypot_hits = _find_honeypot_hits(files_accessed, honeypot_meta)
    executed_scripts = _read_lines(results_path / "executed_scripts.txt")

    return {
        "results_dir": str(results_path),
        "scripts_executed": executed_scripts,
        "file_accesses": sorted(set(files_accessed)),
        "network_attempts": sorted(set(network_attempts)),
        "execve_calls": sorted(set(execs)),
        "honeypot_accesses": sorted(set(honeypot_hits)),
        "suspicious_syscalls": len(honeypot_hits) + len(set(network_attempts)),
    }


def _read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _parse_open_paths(strace_text: str) -> List[str]:
    paths: List[str] = []
    for match in re.finditer(r"(?:open|openat)\([^\"]*\"([^\"]+)\"", strace_text):
        paths.append(match.group(1))
    return paths


def _parse_connect_calls(strace_text: str) -> List[str]:
    attempts: List[str] = []
    for match in re.finditer(r"connect\([^)]*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\(\"([^\"]+)\"\)", strace_text):
        attempts.append(f"{match.group(2)}:{match.group(1)}")
    for match in re.finditer(r"connect\([^)]*sa_data=\"([^\"]+)\"", strace_text):
        attempts.append(match.group(1))
    return attempts


def _parse_execve_calls(strace_text: str) -> List[str]:
    calls: List[str] = []
    for match in re.finditer(r"execve\(\"([^\"]+)\"", strace_text):
        calls.append(match.group(1))
    return calls


def _find_honeypot_hits(accesses: List[str], honeypot_meta: Dict[str, object]) -> List[str]:
    hit_list: List[str] = []
    honeypot_files = honeypot_meta.get("files", {})
    if not isinstance(honeypot_files, dict):
        return hit_list

    relevant_markers = [
        "/home/auditor/.ssh/id_rsa",
        "/home/auditor/.ssh/known_hosts",
        "/home/auditor/.config/openclaw/config.json",
        "/home/auditor/.aws/credentials",
        "/home/auditor/.env",
    ]

    dynamic_markers = [str(path) for path in honeypot_files.values()]
    all_markers = relevant_markers + dynamic_markers

    for accessed in accesses:
        for marker in all_markers:
            if marker in accessed:
                hit_list.append(accessed)
                break
    return hit_list


def sandbox_findings(sandbox_report: Dict[str, object]) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []

    for path in sandbox_report.get("honeypot_accesses", []):
        findings.append(
            {
                "rule": "sandbox_honeypot",
                "category": "sandbox",
                "severity": "CRITICAL",
                "file": path,
                "line": None,
                "message": "Honeypot file accessed during execution",
                "evidence": path,
            }
        )

    for target in sandbox_report.get("network_attempts", []):
        findings.append(
            {
                "rule": "sandbox_network",
                "category": "sandbox",
                "severity": "CRITICAL",
                "file": "<runtime>",
                "line": None,
                "message": "Runtime network connection attempt",
                "evidence": target,
            }
        )

    return findings


def dump_sandbox_json(sandbox_report: Dict[str, object], output_file: str) -> None:
    Path(output_file).write_text(json.dumps(sandbox_report, indent=2), encoding="utf-8")
