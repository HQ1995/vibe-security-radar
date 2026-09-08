#!/usr/bin/env python3
"""Shared JSON cache for build-time GitHub reachability checks."""
from __future__ import annotations

import json
import time
from pathlib import Path

CACHE_PATH = Path(__file__).resolve().parent / ".verify-cache.json"
DEFAULT_TTL = 7 * 24 * 3600  # 7 days


def load() -> dict:
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save(cache: dict) -> None:
    CACHE_PATH.write_text(json.dumps(cache, indent=0, sort_keys=True) + "\n", encoding="utf-8")


def fresh(entry: object, ttl: int = DEFAULT_TTL) -> bool:
    if not isinstance(entry, dict):
        return False
    verified = entry.get("verified_at")
    if not isinstance(verified_at := verified, (int, float)):
        return False
    return time.time() - verified_at < ttl
