from pathlib import Path

from skill_audit.sandbox import analyze_results, sandbox_findings


def test_analyze_results_extracts_honeypot_and_connect(tmp_path: Path):
    strace = tmp_path / "test.strace"
    strace.write_text(
        '\n'.join(
            [
                'openat(AT_FDCWD, "/home/auditor/.ssh/id_rsa", O_RDONLY) = 3',
                'connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.51.100.20")}, 16) = -1 ENETUNREACH',
                'execve("/usr/bin/python3", ["python3", "helper.py"], 0x7ffd) = 0',
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "executed_scripts.txt").write_text("helper.py\n", encoding="utf-8")

    report = analyze_results(
        str(tmp_path),
        {
            "files": {
                ".ssh/id_rsa": "/home/auditor/.ssh/id_rsa",
                ".config/openclaw/config.json": "/home/auditor/.config/openclaw/config.json",
            }
        },
    )

    assert report["scripts_executed"] == ["helper.py"]
    assert "/home/auditor/.ssh/id_rsa" in report["honeypot_accesses"]
    assert "198.51.100.20:443" in report["network_attempts"]
    assert "/usr/bin/python3" in report["execve_calls"]

    findings = sandbox_findings(report)
    severities = {item["severity"] for item in findings}
    assert "CRITICAL" in severities
