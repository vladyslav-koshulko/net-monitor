from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

import yaml


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Paths:
    home: Path
    config: Path
    patterns: Path
    events_jsonl: Path
    ecs_events_jsonl: Path
    summary_json: Path
    baseline_json: Path
    health_json: Path
    runtime_status_json: Path
    notify_jsonl: Path
    pcap_ring_dir: Path
    pcap_evidence_dir: Path


def _pkg_file(filename: str) -> Path:
    return Path(__file__).resolve().parent / filename


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data if isinstance(data, dict) else {}


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def ensure_home(config_home: str | None = None) -> Paths:
    default_home = "~/.net-monitor"
    home = Path(config_home or default_home).expanduser().resolve()
    home.mkdir(parents=True, exist_ok=True)

    pcap_ring_dir = home / "pcap" / "ring"
    pcap_evidence_dir = home / "pcap" / "evidence"
    pcap_ring_dir.mkdir(parents=True, exist_ok=True)
    pcap_evidence_dir.mkdir(parents=True, exist_ok=True)

    paths = Paths(
        home=home,
        config=home / "config.yaml",
        patterns=home / "patterns.yaml",
        events_jsonl=home / "events.jsonl",
        ecs_events_jsonl=home / "events_ecs.jsonl",
        summary_json=home / "summary.json",
        baseline_json=home / "baseline.json",
        health_json=home / "health.json",
        runtime_status_json=home / "runtime_status.json",
        notify_jsonl=home / "notify_queue.jsonl",
        pcap_ring_dir=pcap_ring_dir,
        pcap_evidence_dir=pcap_evidence_dir,
    )

    if not paths.config.exists():
        shutil.copy(_pkg_file("default_config.yaml"), paths.config)
    if not paths.patterns.exists():
        shutil.copy(_pkg_file("default_patterns.yaml"), paths.patterns)

    return paths


def severity_allowed(value: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(value, 1) >= SEVERITY_ORDER.get(minimum, 1)
