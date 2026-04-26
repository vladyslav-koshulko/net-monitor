from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def normalize_cleanup_severity(value: str) -> str:
    raw = str(value or "high").strip().lower()
    if raw in {"all", *SEVERITY_ORDER.keys()}:
        return raw
    return "high"


def _severity_rank(value: str) -> int:
    return SEVERITY_ORDER.get(str(value or "low").strip().lower(), 1)


def _should_clean_severity(event_severity: str, cleanup_below: str) -> bool:
    cleanup_below = normalize_cleanup_severity(cleanup_below)
    if cleanup_below == "all":
        return True
    return _severity_rank(event_severity) < _severity_rank(cleanup_below)


def cleanup_events_file(
    events_path: Path,
    now_ts: int,
    *,
    cleanup_below: str,
    older_than_sec: int,
    force: bool = False,
) -> Tuple[int, int]:
    if not events_path.exists():
        return 0, 0

    older_than_sec = max(1, int(older_than_sec or 1))
    cleanup_below = normalize_cleanup_severity(cleanup_below)

    removed = 0
    kept_lines = []

    try:
        lines = events_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return 0, 0

    for line in lines:
        raw = line.strip()
        if not raw:
            continue

        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            kept_lines.append(raw)
            continue

        if not isinstance(event, dict):
            kept_lines.append(raw)
            continue

        event_severity = str(event.get("severity", "low")).strip().lower()
        event_ts = int(event.get("timestamp", 0) or 0)

        by_severity = _should_clean_severity(event_severity, cleanup_below)
        by_age = force or (event_ts > 0 and (now_ts - event_ts) >= older_than_sec)

        if by_severity and by_age:
            removed += 1
            continue

        kept_lines.append(json.dumps(event, ensure_ascii=False))

    temp_path = events_path.with_suffix(events_path.suffix + ".tmp")
    payload = "\n".join(kept_lines)
    if payload:
        payload += "\n"

    temp_path.write_text(payload, encoding="utf-8")
    temp_path.replace(events_path)
    return removed, len(kept_lines)
