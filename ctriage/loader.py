"""Load CloudTrail records from the formats you actually get handed during an incident."""
from __future__ import annotations

import gzip
import json
from datetime import datetime
from pathlib import Path


def parse_time(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _open(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open(encoding="utf-8")


def load_file(path: str | Path) -> list[dict]:
    """Accepts native CloudTrail ({"Records": [...]}), a bare JSON array, or JSON Lines
    (one event per line, as exported from CloudTrail Lake / Athena / most SIEMs)."""
    path = Path(path)
    with _open(path) as fh:
        text = fh.read()
    stripped = text.lstrip()
    if stripped.startswith("{") and '"Records"' in stripped[:200]:
        return json.loads(text)["Records"]
    if stripped.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def load(paths: list[str | Path]) -> list[dict]:
    records: list[dict] = []
    for p in paths:
        p = Path(p)
        files = sorted(f for f in p.rglob("*") if f.is_file()) if p.is_dir() else [p]
        for f in files:
            if f.name.endswith((".json", ".json.gz", ".jsonl", ".jsonl.gz")):
                records.extend(load_file(f))
    seen, unique = set(), []
    for r in records:  # CloudTrail can deliver duplicates; eventID is the dedupe key
        key = r.get("eventID") or json.dumps(r, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    unique.sort(key=lambda r: r["eventTime"])
    return unique


def actor(r: dict) -> str:
    ui = r.get("userIdentity") or {}
    if ui.get("type") == "Root":
        return "root"
    if ui.get("type") == "AssumedRole":
        return (ui.get("arn") or "").split(":assumed-role/")[-1] or "assumed-role"
    return ui.get("userName") or ui.get("arn") or ui.get("principalId") or ui.get("invokedBy") or "unknown"
