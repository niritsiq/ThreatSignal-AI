"""Utilities for loading and managing the breach case dataset."""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def load_cases(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        logger.warning(f"Breach dataset not found at {path}")
        return []
    with open(p, "r", encoding="utf-8") as f:
        cases = [json.loads(line) for line in f if line.strip()]
    logger.info("Loaded %d breach cases from %s", len(cases), path)
    return cases


def save_cases(cases: list[dict], path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for case in cases:
            f.write(json.dumps(case, ensure_ascii=False) + "\n")
