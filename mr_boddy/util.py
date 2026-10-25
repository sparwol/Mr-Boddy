"""Small CSV and date helpers."""
from __future__ import annotations

import csv
from datetime import date, datetime


def _read(path) -> list[dict]:
    with open(path, newline="") as f:
        return [{k.strip(): (v or "").strip() for k, v in r.items()} for r in csv.DictReader(f)]


def _yes(v: str) -> bool:
    return str(v).strip().lower() in {"yes", "y", "true", "1"}


def _d(v: str) -> date | None:
    try:
        return datetime.fromisoformat(v[:10]).date() if v else None
    except ValueError:
        return None
