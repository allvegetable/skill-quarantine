"""CLI entry point for skill-audit."""

from __future__ import annotations

import argparse
import json
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from skill_audit import __version__
from skill_audit import reporter, sandbox, scanner


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="skill-audit", description="Audit OpenClaw skills for malicious behavior")
    parser.add_argument("target", help="Local skill directory path or URL to archive")
    parser.add_argument("--static-only", action="store_true", help="Run only static scan")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Report output format")
    parser.add_argument("--output", help="Write report to file")
    parser.add_argument("--verbose", action="store_true", help="Show detailed matches")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in text output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args()


def _is_url(value: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    return parsed.scheme in {"http", "https"}


def _prepare_target(target: str):
    if not _is_url(target):
        base = Path(target).resolve()
        if not base.is_dir():
            raise FileNotFoundError(f"Target must be a directory for local scans: {target}")
        return str(base), None

    temp_dir = tempfile.TemporaryDirectory(prefix="skill-audit-target-")
    archive_path = Path(temp_dir.name) / "skill_archive"
    urllib.request.urlretrieve(target, archive_path)

    extract_dir = Path(temp_dir.name) / "skill"
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(extract_dir)
    except zipfile.BadZipFile:
        with tarfile.open(archive_path) as tf:
            tf.extractall(extract_dir)

    subdirs = [p for p in extract_dir.iterdir() if p.is_dir()]
    resolved = subdirs[0] if len(subdirs) == 1 else extract_dir
    return str(resolved), temp_dir


def main() -> int:
    args = parse_args()

    temp_ref = None
    try:
        skill_dir, temp_ref = _prepare_target(args.target)
        static_report = scanner.scan_skill(skill_dir)

        sandbox_report = None
        findings = list(static_report["findings"])
        if not args.static_only:
            sandbox_report = sandbox.run_sandbox(skill_dir)
            findings.extend(sandbox.sandbox_findings(sandbox_report))

        skill_name = Path(skill_dir).name
        report = reporter.build_report(skill_name, static_report, sandbox_report, findings)

        if args.format == "json":
            output = json.dumps(report, indent=2)
        else:
            output = reporter.render_text(report, use_color=not args.no_color, verbose=args.verbose)

        print(output)

        if args.output:
            if args.format == "json":
                Path(args.output).write_text(output + "\n", encoding="utf-8")
            else:
                reporter.write_report(report, args.output)

        return 0
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: {exc}")
        return 1
    finally:
        if temp_ref is not None:
            temp_ref.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
