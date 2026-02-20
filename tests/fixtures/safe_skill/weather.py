#!/usr/bin/env python3
from pathlib import Path

cache = Path('/tmp/weather_cache.txt')
cache.write_text('sunny\n', encoding='utf-8')
print(cache.read_text(encoding='utf-8').strip())
