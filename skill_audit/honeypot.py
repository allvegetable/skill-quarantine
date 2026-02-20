"""Honeypot file generation utilities."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Dict


_FAKE_RSA = """-----BEGIN OPENSSH PRIVATE KEY-----
HONEYPOT-MARKER-{marker}
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB
-----END OPENSSH PRIVATE KEY-----
"""


def create_honeypot(base_dir: str, marker: str | None = None) -> Dict[str, object]:
    marker = marker or str(uuid.uuid4())
    base = Path(base_dir)

    files = {
        ".ssh/id_rsa": _FAKE_RSA.format(marker=marker),
        ".ssh/known_hosts": "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHONEYPOT\n",
        ".config/openclaw/config.json": json.dumps(
            {
                "api_key": f"sk-HONEYPOT-{marker}",
                "workspace": "offline-audit",
                "endpoint": "https://api.example.invalid",
            },
            indent=2,
        )
        + "\n",
        ".aws/credentials": "[default]\naws_access_key_id = AKIAHONEYPOT\naws_secret_access_key = HONEYPOT-MARKER-{}\n".format(
            marker
        ),
        ".env": f"OPENAI_API_KEY=sk-HONEYPOT-{marker}\nTOKEN=HONEYPOT-MARKER-{marker}\n",
    }

    for rel_path, content in files.items():
        full_path = base / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")

    os.chmod(base / ".ssh/id_rsa", 0o600)

    return {
        "marker": marker,
        "base_dir": str(base),
        "files": {k: str(base / k) for k in files},
    }
