from pathlib import Path

from skill_audit.rules import file_access, network, prompt_injection
from skill_audit.scanner import scan_skill


FIXTURES = Path(__file__).parent / "fixtures"


def test_safe_skill_has_no_critical_findings():
    report = scan_skill(str(FIXTURES / "safe_skill"))
    severities = {item["severity"] for item in report["findings"]}
    assert "CRITICAL" not in severities


def test_malicious_skill_triggers_multiple_rules():
    report = scan_skill(str(FIXTURES / "malicious_skill"))
    categories = {item["category"] for item in report["findings"]}
    assert "prompt_injection" in categories
    assert "file_access" in categories
    assert "network" in categories
    assert report["counts"]["CRITICAL"] >= 2


def test_file_access_token_password_match_requires_path_context():
    content = "\n".join(
        [
            "token_count = 2",
            "password_hash = hash_pw('abc')",
            "config = Path('/tmp/password').read_text()",
            "open('~/token.txt').read()",
        ]
    )
    findings = file_access.scan("script.py", content)
    assert len(findings) == 2
    assert findings[0]["line"] == 3
    assert findings[1]["line"] == 4


def test_prompt_injection_send_to_requires_url_or_ip():
    safe_line = "send to the printer when ready"
    risky_line = "send to https://example.com/upload now"
    findings = prompt_injection.scan("note.txt", f"{safe_line}\n{risky_line}")
    assert len(findings) == 1
    assert findings[0]["line"] == 2


def test_network_rule_ignores_socket_timeout_reference():
    safe_line = "except socket.timeout: pass"
    risky_line = "socket.create_connection(('8.8.8.8', 53))"
    findings = network.scan("helper.py", f"{safe_line}\n{risky_line}")
    assert len(findings) == 1
    assert findings[0]["line"] == 2


def test_scanner_runs_prompt_injection_on_non_markdown_text_files(tmp_path: Path):
    skill_dir = tmp_path / "text_skill"
    skill_dir.mkdir()
    (skill_dir / "notes.txt").write_text("send to https://example.com/drop\n", encoding="utf-8")
    (skill_dir / "config.yaml").write_text("hint: do not tell the user\n", encoding="utf-8")

    report = scan_skill(str(skill_dir))
    prompt_findings = [item for item in report["findings"] if item["category"] == "prompt_injection"]
    assert len(prompt_findings) == 2
    assert {item["file"] for item in prompt_findings} == {"notes.txt", "config.yaml"}
