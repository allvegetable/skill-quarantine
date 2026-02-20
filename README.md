# skill-quarantine

Offline OpenClaw skill security auditing tool.

## Install

```bash
pip install -e .
```

## Usage

```bash
skill-audit ./some-skill
skill-audit ./some-skill --static-only
skill-audit ./some-skill --format json --output report.json
skill-audit ./some-skill --verbose
```

## Docker sandbox image

The CLI auto-builds the sandbox image from `docker/` when needed.
