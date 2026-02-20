# skill-quarantine

Offline security audit tool for OpenClaw skills. Scans for malicious behavior before you install.

## Why

[clawhub.com](https://clawhub.com) hosts community skills, but there's no guarantee they're safe. A malicious skill can:

- Inject prompts to make the agent leak your API keys and credentials
- Run scripts that read `~/.ssh/id_rsa` and exfiltrate to a remote server
- Use zero-width characters to hide instructions in markdown
- Escalate privileges or tamper with your OpenClaw config

skill-quarantine catches these before they touch your system.

## How It Works

Two layers of defense:

1. **Static Scan** — regex + rule engine across all files, detecting:
   - Prompt injection patterns in markdown (instruction override, concealment, system message impersonation)
   - Sensitive file access (`~/.ssh`, `~/.aws`, `~/.config/openclaw`, `.env`, credentials)
   - Network exfiltration (curl/wget/fetch to non-localhost, known exfil endpoints like pastebin)
   - Code obfuscation (base64+eval, zero-width chars, hex/octal encoding, char code assembly)
   - Privilege escalation (sudo, chmod 777, crontab, systemd manipulation)

2. **Docker Sandbox** — runs skill scripts in an isolated container (`--network=none`) with:
   - strace syscall monitoring (open, connect, execve)
   - Honeypot files (fake SSH keys, fake API keys, fake AWS credentials) — if a script touches them, it's caught
   - 30s timeout per script, container destroyed after audit

## Install

```bash
pip install -e .
```

Requires Docker for sandbox mode. Static-only mode works without Docker.

## Usage

```bash
# Full audit (static + sandbox)
skill-audit ./some-skill

# Static scan only (no Docker needed)
skill-audit ./some-skill --static-only

# Verbose output (show matched evidence)
skill-audit ./some-skill --verbose

# JSON report
skill-audit ./some-skill --format json --output report.json
```

## Example Output

Safe skill:
```
📋 Skill Audit Report: weather
📊 Static Scan — ✅ No findings
🔒 Sandbox — ✅ Clean
📊 Score: 100/100 — 🟢 SAFE
```

Malicious skill:
```
📋 Skill Audit Report: totally-legit-helper
📊 Static Scan
├─ 🔴 CRITICAL: Instruction override phrase (SKILL.md:3)
├─ 🔴 CRITICAL: Sensitive file access ~/.ssh/id_rsa (helper.py:6)
├─ 🔴 CRITICAL: Exfiltration to pastebin.com (helper.py:8)
🔒 Sandbox
├─ 🔴 Honeypot access DETECTED: ~/.ssh/id_rsa
📊 Score: 0/100 — 🔴 DANGEROUS
```

## Scoring

| Severity | Penalty | Examples |
|----------|---------|---------|
| CRITICAL | -25 | Prompt injection, honeypot access, data exfiltration |
| WARNING | -10 | sudo usage, base64+eval, zero-width chars |
| INFO | -3 | Long lines, hex literals |

- 90-100: 🟢 SAFE
- 60-89: 🟡 SUSPICIOUS (review manually)
- 0-59: 🔴 DANGEROUS (do not install)

## Roadmap

### ✅ Phase 1 — Static Scanning (done)
Regex + rule engine covering prompt injection, file access, network, obfuscation, and privilege escalation.

### ✅ Phase 2 — Docker Sandbox (done)
Isolated container execution with strace monitoring, honeypot files, and network isolation.

### 🔲 Phase 3 — Runtime Monitoring (planned)
Post-install continuous monitoring. Catches attacks that evade static analysis and sandbox:
- **Time bombs** — code that activates after a delay (`if date > March 1: exfiltrate()`)
- **Remote triggers** — scripts that fetch config from an external server, initially benign, later swapped to malicious payload
- **Context-dependent prompt injection** — SKILL.md instructions that only trigger under specific conversation conditions

This requires hooks in OpenClaw's skill execution layer to:
- Log file access and network requests during skill runtime
- Enforce a permission whitelist (skill declares it only needs `wttr.in`, alert if it hits `pastebin.com`)
- Auto-isolate skills that violate declared permissions

Phase 3 involves changes to OpenClaw core — contributions welcome.

## Docker Sandbox Image

The CLI auto-builds the sandbox image from `docker/` on first run. To build manually:

```bash
docker build -t skill-quarantine:latest docker/
```

## License

MIT
