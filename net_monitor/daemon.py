#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
import re
import subprocess
import time
from concurrent.futures import Future, ThreadPoolExecutor
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit
from urllib.request import Request, urlopen

from scapy.all import IP, IPv6, Raw, TCP, UDP, sniff, wrpcap  # type: ignore

from .config import ensure_home, load_yaml, read_json, severity_allowed, write_json
from .rules import collect_exceptions, ignored_by_exception, load_pattern_rules, match_patterns, min_severity
from .tls_audit import parse_tls_metadata


LEGACY_PORTS = {
    21: ("FTP plaintext", "high"),
    23: ("Telnet plaintext", "critical"),
    25: ("SMTP plaintext", "medium"),
    110: ("POP3 plaintext", "high"),
    143: ("IMAP plaintext", "high"),
    389: ("LDAP plaintext", "high"),
}
SEVERITY_WEIGHTS = {"low": 1, "medium": 3, "high": 6, "critical": 10}
TOKEN_CANDIDATE = re.compile(r"\b[A-Za-z0-9_-]{20,}\b")
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


@dataclass
class State:
    total_packets: int = 0
    target_packets: int = 0
    payload_packets: int = 0
    alerts_emitted: int = 0
    alerts_suppressed: int = 0
    dropped_packets: int = 0
    risk_score: int = 0
    start_ts: int = 0


def _proto_name(sport: int, dport: int, layer: str) -> str:
    ports = {sport, dport}
    if layer == "UDP" and 53 in ports:
        return "DNS"
    if 443 in ports or 8443 in ports:
        return "TLS"
    if 80 in ports or 8080 in ports or 8000 in ports:
        return "HTTP"
    if 22 in ports:
        return "SSH"
    if 23 in ports:
        return "TELNET"
    if 21 in ports:
        return "FTP"
    return layer


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _to_ecs_event(event: Dict[str, Any]) -> Dict[str, Any]:
    attack = event.get("attack", []) if isinstance(event.get("attack"), list) else []
    ecs = {
        "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event.get("timestamp", 0))),
        "event": {
            "kind": "alert",
            "category": ["network", "intrusion_detection"],
            "type": ["info"],
            "severity": event.get("severity", "low"),
            "id": event.get("event_id"),
        },
        "source": {"ip": event.get("src_ip"), "port": event.get("src_port")},
        "destination": {"ip": event.get("dst_ip"), "port": event.get("dst_port")},
        "network": {"transport": str(event.get("protocol", "")).lower()},
        "tags": ["net-monitor", "passive-audit"],
        "rule": {
            "name": ", ".join(m.get("rule_name", "") for m in event.get("matches", [])[:8]),
        },
        "net_monitor": {
            "issues": event.get("issues", []),
            "tls": event.get("tls", {}),
            "risk_score": int(event.get("risk_score", 0) or 0),
            "fingerprints": event.get("fingerprints", {}),
            "device": event.get("device", {}),
        },
    }
    if attack:
        ecs["threat"] = {
            "framework": "MITRE ATT&CK",
            "technique": [
                {
                    "id": str(x.get("id", "")),
                    "name": str(x.get("name", "")),
                }
                for x in attack
            ],
        }
    return ecs


def _write_text_line(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(line)


def _http_probe(url: str, timeout_sec: int = 3) -> bool:
    try:
        req = Request(url, method="GET")
        with urlopen(req, timeout=timeout_sec) as resp:
            code = int(resp.getcode() or 0)
            return 200 <= code < 500
    except Exception:
        return False


def _probe_loki_endpoint(push_url: str, timeout_sec: int = 3) -> bool:
    val = str(push_url or "").strip()
    if not val:
        return False
    ready_url = val
    marker = "/loki/api/v1/push"
    if marker in val:
        ready_url = val.split(marker, 1)[0].rstrip("/") + "/ready"
    return _http_probe(ready_url, timeout_sec=timeout_sec)


def _probe_elastic_endpoint(base_or_bulk_url: str, timeout_sec: int = 3) -> bool:
    val = str(base_or_bulk_url or "").strip()
    if not val:
        return False
    probe_url = val
    if probe_url.endswith("/_bulk"):
        probe_url = probe_url[: -len("/_bulk")]
    return _http_probe(probe_url, timeout_sec=timeout_sec)


def _push_loki_batch(url: str, items: List[Dict[str, Any]], timeout_sec: int = 3) -> bool:
    streams_map: Dict[str, Dict[str, Any]] = {}
    for item in items:
        labels = item.get("labels", {}) if isinstance(item.get("labels"), dict) else {}
        line = str(item.get("line", ""))
        ts = int(item.get("ts", time.time()) or time.time())
        ns = str(ts * 1_000_000_000)
        key = json.dumps(labels, sort_keys=True, ensure_ascii=False)
        bucket = streams_map.setdefault(key, {"stream": labels, "values": []})
        bucket["values"].append([ns, line])
    payload = {"streams": list(streams_map.values())}

    try:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        with urlopen(req, timeout=timeout_sec) as resp:
            code = int(resp.getcode() or 0)
            return 200 <= code < 300
    except Exception:
        return False


def _push_elastic_bulk(
    bulk_url: str,
    index_name: str,
    items: List[Dict[str, Any]],
    timeout_sec: int = 3,
    api_key: str = "",
    username: str = "",
    password: str = "",
) -> bool:
    chunks: List[str] = []
    for item in items:
        chunks.append(json.dumps({"index": {"_index": index_name}}, ensure_ascii=False))
        chunks.append(json.dumps(item, ensure_ascii=False))
    body = "\n".join(chunks) + "\n"

    try:
        req = Request(bulk_url, data=body.encode("utf-8"), method="POST")
        req.add_header("Content-Type", "application/x-ndjson")
        api_key_val = str(api_key or "").strip()
        if api_key_val:
            req.add_header("Authorization", f"ApiKey {api_key_val}")
        elif username and password:
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            req.add_header("Authorization", f"Basic {token}")

        with urlopen(req, timeout=timeout_sec) as resp:
            code = int(resp.getcode() or 0)
            if not (200 <= code < 300):
                return False
            raw = resp.read().decode("utf-8", errors="ignore")
            if not raw.strip():
                return True
            try:
                parsed = json.loads(raw)
                return not bool(parsed.get("errors", False))
            except Exception:
                return True
    except Exception:
        return False


def _extract_http_info(payload_text: str) -> Dict[str, Any]:
    lines = payload_text.splitlines()
    if not lines:
        return {}
    first = lines[0].strip()
    if not any(first.startswith(m + " ") for m in HTTP_METHODS):
        return {}
    parts = first.split(" ")
    if len(parts) < 2:
        return {}
    method = parts[0]
    path = parts[1]
    host = ""
    ua = ""
    for line in lines[1:20]:
        low = line.lower()
        if low.startswith("host:"):
            host = line.split(":", 1)[1].strip()
        elif low.startswith("user-agent:"):
            ua = line.split(":", 1)[1].strip()
    return {
        "method": method,
        "path": path,
        "host": host,
        "user_agent": ua[:120],
        "request_line": first[:200],
    }


def _extract_smtp_info(payload_text: str) -> Dict[str, Any]:
    lines = [x.strip() for x in payload_text.splitlines() if x.strip()]
    if not lines:
        return {}
    smtp_markers = ("HELO", "EHLO", "MAIL FROM:", "RCPT TO:", "DATA", "QUIT", "250 ", "220 ")
    has_smtp = any(any(line.upper().startswith(m) for m in smtp_markers) for line in lines[:12])
    if not has_smtp:
        return {}
    from_addr = ""
    rcpt = ""
    command = lines[0][:120]
    for line in lines[:20]:
        up = line.upper()
        if up.startswith("MAIL FROM:"):
            from_addr = line.split(":", 1)[1].strip()
        elif up.startswith("RCPT TO:"):
            rcpt = line.split(":", 1)[1].strip()
    return {
        "command": command,
        "mail_from": from_addr[:120],
        "rcpt_to": rcpt[:120],
    }


def _extract_dns_query(payload_bytes: bytes) -> str:
    if len(payload_bytes) < 13:
        return ""
    idx = 12
    labels: List[str] = []
    while idx < len(payload_bytes):
        ln = payload_bytes[idx]
        idx += 1
        if ln == 0:
            break
        if idx + ln > len(payload_bytes):
            return ""
        chunk = payload_bytes[idx:idx + ln]
        idx += ln
        try:
            label = chunk.decode("ascii", errors="ignore")
        except Exception:
            return ""
        if not label:
            return ""
        labels.append(label)
        if len(labels) > 12:
            break
    if not labels:
        return ""
    name = ".".join(labels)
    if len(name) > 255:
        return ""
    return name


def _extract_dns_info(payload_bytes: bytes, sport: int, dport: int) -> Dict[str, Any]:
    if 53 not in {sport, dport}:
        return {}
    qname = _extract_dns_query(payload_bytes)
    return {"query": qname} if qname else {}


def _parse_host_port(token: str) -> Tuple[str, int]:
    val = token.strip()
    if not val:
        return "", 0
    if val.startswith("[") and "]:" in val:
        host, port = val[1:].split("]:", 1)
        return host, int(port) if port.isdigit() else 0
    if ":" in val:
        host, port = val.rsplit(":", 1)
        return host, int(port) if port.isdigit() else 0
    return val, 0


def _sample_by_fingerprint(fp: str, keep_ratio: float) -> bool:
    ratio = max(0.0, min(1.0, float(keep_ratio)))
    if ratio >= 1.0:
        return True
    if ratio <= 0.0:
        return False
    hv = int(hashlib.sha1(fp.encode("utf-8", errors="ignore")).hexdigest()[:8], 16) % 10000
    return hv < int(ratio * 10000)


def _event_risk_score(severity: str, issues: List[Dict[str, Any]], matches: List[Dict[str, Any]], has_behavior_anomaly: bool) -> int:
    base_map = {"low": 20, "medium": 45, "high": 70, "critical": 90}
    score = int(base_map.get(str(severity).lower(), 20))
    score += min(15, len(issues) * 3)
    score += min(10, len(matches) * 2)
    if has_behavior_anomaly:
        score += 10
    return max(0, min(100, score))


def _map_attack_techniques(
    issues: List[Dict[str, Any]],
    http_info: Dict[str, Any],
    dns_info: Dict[str, Any],
    has_behavior_anomaly: bool,
) -> List[Dict[str, str]]:
    mapped: Dict[str, Dict[str, str]] = {}

    issue_titles = " | ".join(str(x.get("title", "")).lower() for x in issues)
    if "weak tls" in issue_titles or "auth header outside tls" in issue_titles:
        mapped["T1040"] = {"id": "T1040", "name": "Network Sniffing"}
    if has_behavior_anomaly:
        mapped["T1595"] = {"id": "T1595", "name": "Active Scanning"}

    q = str(dns_info.get("query", "")).lower()
    if q:
        mapped["T1071.004"] = {"id": "T1071.004", "name": "Application Layer Protocol: DNS"}
        if any(x in q for x in ("dyn", "ddns", "no-ip", "duckdns")):
            mapped["T1568.003"] = {"id": "T1568.003", "name": "Dynamic Resolution: DNS Calculation"}

    path = str(http_info.get("path", "")).lower()
    if path and any(x in path for x in ("/wp-admin", "/admin", "/login", "/phpmyadmin", "/cgi-bin")):
        mapped["T1190"] = {"id": "T1190", "name": "Exploit Public-Facing Application"}

    return list(mapped.values())


def _infer_device_profile(protocol: str, sport: int, dport: int, http_info: Dict[str, Any]) -> Dict[str, Any]:
    hints: Dict[str, int] = {}
    ports = {int(sport or 0), int(dport or 0)}
    ua = str(http_info.get("user_agent", "")).lower()

    if any(p in ports for p in (554, 8554, 8000, 8081)):
        hints["camera/iot"] = hints.get("camera/iot", 0) + 3
    if any(p in ports for p in (1883, 8883, 5683)):
        hints["iot/sensor"] = hints.get("iot/sensor", 0) + 3
    if any(p in ports for p in (9100, 515, 631)):
        hints["printer"] = hints.get("printer", 0) + 3
    if any(p in ports for p in (3389, 445, 139)):
        hints["windows-host"] = hints.get("windows-host", 0) + 2
    if any(p in ports for p in (22, 2375, 2376, 6443)):
        hints["server"] = hints.get("server", 0) + 1

    if "android" in ua:
        hints["android-device"] = hints.get("android-device", 0) + 4
    if "iphone" in ua or "ipad" in ua or "ios" in ua:
        hints["ios-device"] = hints.get("ios-device", 0) + 4
    if "windows" in ua:
        hints["windows-host"] = hints.get("windows-host", 0) + 2
    if "mac os" in ua or "macintosh" in ua:
        hints["mac-device"] = hints.get("mac-device", 0) + 2
    if protocol in {"dns", "http", "tls"} and not hints:
        hints["workstation"] = 1

    if not hints:
        return {"type": "unknown", "confidence": 0.0, "reason": []}

    sorted_hints = sorted(hints.items(), key=lambda x: x[1], reverse=True)
    best_name, best_score = sorted_hints[0]
    max_score = max(1, sum(v for _, v in sorted_hints))
    confidence = min(1.0, float(best_score) / float(max_score))
    return {
        "type": best_name,
        "confidence": round(confidence, 2),
        "reason": [k for k, _ in sorted_hints[:3]],
    }


def _collect_process_map(timeout_sec: int = 3) -> Dict[Tuple[str, int, str, int], Dict[str, Any]]:
    try:
        proc = subprocess.run(["ss", "-tunp"], capture_output=True, text=True, timeout=timeout_sec, check=False)
    except Exception:
        return {}
    if proc.returncode != 0:
        return {}

    out = proc.stdout or ""
    line_re = re.compile(r"users:\(\(\"([^\"]+)\",pid=(\d+)")
    new_cache: Dict[Tuple[str, int, str, int], Dict[str, Any]] = {}
    for raw in out.splitlines()[1:]:
        parts = raw.split()
        if len(parts) < 6:
            continue
        proto = parts[0].lower()
        local = parts[-3]
        peer = parts[-2]
        proc_part = parts[-1]
        m = line_re.search(proc_part)
        if not m:
            continue
        pname = m.group(1)
        pid = int(m.group(2))
        src_ip, src_port = _parse_host_port(local)
        dst_ip, dst_port = _parse_host_port(peer)
        if not src_ip or not dst_ip or src_port <= 0 or dst_port <= 0:
            continue
        process_info = {"pid": pid, "name": pname, "transport": proto}
        key = (src_ip, src_port, dst_ip, dst_port)
        rev_key = (dst_ip, dst_port, src_ip, src_port)
        new_cache[key] = process_info
        new_cache[rev_key] = process_info
    return new_cache


def _refresh_process_map(cache: Dict[Tuple[str, int, str, int], Dict[str, Any]], timeout_sec: int = 3) -> None:
    new_cache = _collect_process_map(timeout_sec=timeout_sec)
    cache.clear()
    cache.update(new_cache)


def _resolve_geo_asn(ip: str, cache: Dict[str, Dict[str, str]], timeout_sec: int = 3) -> Dict[str, str]:
    if ip in cache:
        return cache[ip]
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            payload = {
                "scope": "local",
                "country": "LOCAL",
                "asn": "LOCAL",
                "org": "local-network",
            }
            cache[ip] = payload
            return payload
    except ValueError:
        payload = {"scope": "unknown", "country": "-", "asn": "-", "org": "-"}
        cache[ip] = payload
        return payload

    payload = {"scope": "external", "country": "-", "asn": "-", "org": "-"}
    try:
        proc = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=timeout_sec, check=False)
        text = (proc.stdout or "") + "\n" + (proc.stderr or "")
        for line in text.splitlines():
            low = line.lower()
            if payload["asn"] == "-" and (low.startswith("origin:") or low.startswith("originas:") or low.startswith("aut-num:")):
                payload["asn"] = line.split(":", 1)[1].strip()[:64]
            elif payload["country"] == "-" and low.startswith("country:"):
                payload["country"] = line.split(":", 1)[1].strip()[:32]
            elif payload["org"] == "-" and (low.startswith("orgname:") or low.startswith("org-name:") or low.startswith("descr:")):
                payload["org"] = line.split(":", 1)[1].strip()[:120]
            if payload["asn"] != "-" and payload["country"] != "-" and payload["org"] != "-":
                break
    except Exception:
        pass
    cache[ip] = payload
    return payload


def _parse_targets(cfg: Dict[str, Any]) -> Tuple[str, List[ipaddress._BaseNetwork], List[Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]]]:
    target_cfg = cfg.get("capture", {}).get("targets", {})
    mode = str(target_cfg.get("mode", "all"))
    networks: List[ipaddress._BaseNetwork] = []
    ranges: List[Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]] = []

    for ip in target_cfg.get("ips", []):
        try:
            networks.append(ipaddress.ip_network(f"{ip}/32", strict=False))
        except Exception:
            pass
    for net in target_cfg.get("subnets", []):
        try:
            networks.append(ipaddress.ip_network(str(net), strict=False))
        except Exception:
            pass
    for r in target_cfg.get("ranges", []):
        try:
            left, right = str(r).split("-")
            ranges.append((ipaddress.ip_address(left.strip()), ipaddress.ip_address(right.strip())))
        except Exception:
            pass

    return mode, networks, ranges


def _ip_in_ranges(addr: ipaddress._BaseAddress, ranges: List[Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]]) -> bool:
    for a, b in ranges:
        if int(a) <= int(addr) <= int(b):
            return True
    return False


def _target_match(src: str, dst: str, mode: str, nets: List[ipaddress._BaseNetwork], ranges) -> bool:
    if mode == "all":
        return True
    try:
        s = ipaddress.ip_address(src)
        d = ipaddress.ip_address(dst)
    except ValueError:
        return False
    if mode in ("ips", "subnets"):
        return any(s in n or d in n for n in nets)
    if mode == "ranges":
        return _ip_in_ranges(s, ranges) or _ip_in_ranges(d, ranges)
    return any(s in n or d in n for n in nets) or _ip_in_ranges(s, ranges) or _ip_in_ranges(d, ranges)


def _port_allowed(sport: int, dport: int, cfg: Dict[str, Any]) -> bool:
    p = cfg.get("capture", {}).get("ports", {})
    mode = p.get("mode", "all")
    if mode == "all":
        return True
    if mode == "list":
        allowed = {int(x) for x in p.get("list", [])}
        return sport in allowed or dport in allowed
    if mode == "range":
        for raw in p.get("ranges", []):
            try:
                a, b = str(raw).split("-")
                lo, hi = int(a), int(b)
                if lo <= sport <= hi or lo <= dport <= hi:
                    return True
            except Exception:
                continue
    return True


def _protocol_allowed(proto_name: str, cfg: Dict[str, Any]) -> bool:
    protos = [str(x).lower() for x in cfg.get("capture", {}).get("protocols", ["all"])]
    if "all" in protos:
        return True
    return proto_name.lower() in protos


def _write_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _touch_health(paths, state: State, protocol_counter: Counter, issues_by_sev: Counter) -> None:
    payload = {
        "heartbeat_ts": int(time.time()),
        "uptime_sec": int(time.time()) - state.start_ts,
        "packets": {
            "total": state.total_packets,
            "target": state.target_packets,
            "payload": state.payload_packets,
            "alerts": state.alerts_emitted,
            "suppressed": state.alerts_suppressed,
            "dropped": state.dropped_packets,
        },
        "risk_score": state.risk_score,
        "protocols": dict(protocol_counter),
        "issues_by_severity": dict(issues_by_sev),
        "self_checks": {
            "config_exists": paths.config.exists(),
            "patterns_exists": paths.patterns.exists(),
            "storage_writable": paths.home.exists(),
        },
    }
    write_json(paths.health_json, payload)
    write_json(paths.runtime_status_json, payload)


def _load_baseline(paths) -> Dict[str, Any]:
    data = read_json(paths.baseline_json)
    return data if isinstance(data, dict) else {}


def _save_baseline(paths, baseline: Dict[str, Any]) -> None:
    write_json(paths.baseline_json, baseline)


def _store_summary(
    paths,
    state: State,
    protocol_counter: Counter,
    issues: Dict[str, Dict[str, Any]],
    protocol_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    flow_counter: Optional[Counter] = None,
    behavior_counter: Optional[Counter] = None,
    attack_counter: Optional[Counter] = None,
    asset_inventory: Optional[Dict[str, Dict[str, Any]]] = None,
) -> None:
    sev = Counter(v.get("severity", "low") for v in issues.values())
    cipher_score = max(0, 100 - (sev.get("critical", 0) * 18 + sev.get("high", 0) * 9 + sev.get("medium", 0) * 4))
    tls_score = max(0, 100 - (sev.get("critical", 0) * 20 + sev.get("high", 0) * 10 + sev.get("medium", 0) * 5))
    payload = {
        "generated_at": int(time.time()),
        "risk_score": state.risk_score,
        "cipher_score": cipher_score,
        "tls_score": tls_score,
        "packets": {
            "total": state.total_packets,
            "target": state.target_packets,
            "payload": state.payload_packets,
            "alerts": state.alerts_emitted,
            "suppressed": state.alerts_suppressed,
            "dropped": state.dropped_packets,
        },
        "protocol_inventory": dict(protocol_counter),
        "issues_by_severity": dict(sev),
        "issues": list(issues.values()),
        "protocol_tables": protocol_tables or {"http": [], "dns": [], "smtp": []},
        "flow_graph": {
            "top_edges": [
                {"edge": edge, "count": count}
                for edge, count in (flow_counter.most_common(80) if flow_counter else [])
            ],
        },
        "behavior": {
            "anomalies": dict(behavior_counter or {}),
        },
        "attack_techniques": [
            {"id": tid, "count": int(cnt)}
            for tid, cnt in (attack_counter.most_common(30) if attack_counter else [])
        ],
        "asset_inventory": sorted(
            (asset_inventory or {}).values(),
            key=lambda x: int(x.get("hits", 0) or 0),
            reverse=True,
        )[:200],
    }
    write_json(paths.summary_json, payload)


def run_daemon(config_path: Optional[str] = None, once: bool = False, home_path: Optional[str] = None) -> None:
    home_override = home_path or os.environ.get("NET_MONITOR_HOME")
    paths = ensure_home(config_home=home_override)
    cfg = load_yaml(Path(config_path).expanduser()) if config_path else load_yaml(paths.config)
    patterns_data = load_yaml(paths.patterns)
    rules = load_pattern_rules(patterns_data)
    exceptions = collect_exceptions(patterns_data)

    state = State(start_ts=int(time.time()))
    protocol_counter: Counter = Counter()
    issue_registry: Dict[str, Dict[str, Any]] = {}
    issue_severity_counter: Counter = Counter()
    dedupe: Dict[str, Dict[str, float]] = {}
    process_map: Dict[Tuple[str, int, str, int], Dict[str, Any]] = {}
    geo_cache: Dict[str, Dict[str, str]] = {}
    flow_counter: Counter = Counter()
    behavior_counter: Counter = Counter()
    attack_counter: Counter = Counter()
    asset_inventory: Dict[str, Dict[str, Any]] = {}

    baseline = _load_baseline(paths)
    baseline_proto = Counter(baseline.get("protocol_inventory", {}))
    baseline_total = int(baseline.get("total_packets", 0))

    tcp_streams: Dict[Tuple[str, str, int, int], bytearray] = {}
    ring: Deque[Tuple[float, Any]] = deque(maxlen=int(cfg.get("evidence", {}).get("max_ring_packets", 10000)))
    pending_evidence: List[Dict[str, Any]] = []

    stats_interval = int(cfg.get("runtime", {}).get("stats_interval_sec", 5))
    health_interval = int(cfg.get("runtime", {}).get("health_interval_sec", 5))
    stream_max = int(cfg.get("runtime", {}).get("tcp_stream_max_bytes", 131072))

    storage_cfg = cfg.get("storage", {})
    adaptive_cfg = storage_cfg.get("adaptive_flush_batching", {}) if isinstance(storage_cfg.get("adaptive_flush_batching"), dict) else {}
    flush_interval = max(5, int(storage_cfg.get("flush_interval_sec", 60) or 60))
    adaptive_flush_enabled = bool(storage_cfg.get("adaptive_flush", adaptive_cfg.get("enabled", True)))
    flush_batch_min = max(10, int(storage_cfg.get("flush_batch_min", adaptive_cfg.get("batch_size", 80)) or 80))
    flush_batch_max = max(flush_batch_min, int(storage_cfg.get("flush_batch_max", 1200) or 1200))
    flush_burst_pps_hint = float(storage_cfg.get("burst_pps_hint", 1500) or 1500)
    save_events_jsonl = bool(storage_cfg.get("save_events_jsonl", True))
    save_ecs_jsonl = bool(storage_cfg.get("save_ecs_jsonl", True))
    save_notify_jsonl = bool(storage_cfg.get("save_notify_jsonl", True))
    save_decoded_payloads = bool(storage_cfg.get("save_decoded_payloads", True))
    min_severity_to_save = str(storage_cfg.get("min_severity_to_save", "low")).lower()
    decoded_payloads_path = paths.home / "decoded_payloads.jsonl"

    last_stats = time.time()
    last_health = time.time()
    last_summary = time.time()
    last_flush = time.time()
    last_flush_packets = 0

    events_buffer: List[Dict[str, Any]] = []
    ecs_buffer: List[Dict[str, Any]] = []
    notify_buffer: List[Dict[str, Any]] = []
    decoded_payloads_buffer: List[Dict[str, Any]] = []

    min_sev = cfg.get("rules", {}).get("min_severity", "low")
    dedupe_window = int(cfg.get("rules", {}).get("dedupe_window_sec", 20))
    min_repeat = int(cfg.get("rules", {}).get("min_repeat", 1))
    behavior_cfg = cfg.get("behavior", {})
    behavior_enabled = bool(behavior_cfg.get("enabled", True))
    behavior_window_sec = int(behavior_cfg.get("dst_burst_window_sec", 20) or 20)
    behavior_burst_threshold = int(behavior_cfg.get("dst_burst_threshold", 40) or 40)
    dst_activity: Dict[str, Deque[float]] = {}
    process_refresh_sec = int(cfg.get("enrichment", {}).get("process_refresh_sec", 5) or 5)
    process_enabled = bool(cfg.get("enrichment", {}).get("process_correlation", True))
    geo_enabled = bool(cfg.get("enrichment", {}).get("geo_asn", True))
    geo_ttl_sec = int(cfg.get("enrichment", {}).get("geo_ttl_sec", 21600) or 21600)
    geo_workers = max(1, int(cfg.get("enrichment", {}).get("geo_workers", 2) or 2))
    last_process_refresh = 0.0
    enrichment_pool = ThreadPoolExecutor(max_workers=geo_workers + 1)
    process_future: Optional[Future] = None
    geo_futures: Dict[str, Future] = {}
    geo_cache_expiry: Dict[str, float] = {}

    sampling_cfg = behavior_cfg.get("low_severity_sampling", {}) if isinstance(behavior_cfg.get("low_severity_sampling"), dict) else {}
    low_sampling_enabled = bool(sampling_cfg.get("enabled", True))
    low_sampling_burst_pps = float(sampling_cfg.get("burst_pps", 1200) or 1200)
    low_sampling_keep_ratio = float(sampling_cfg.get("keep_ratio", 0.35) or 0.35)

    exports_cfg = cfg.get("exports", {})
    loki_cfg = exports_cfg.get("loki") or {}
    elastic_cfg = exports_cfg.get("elastic") or {}

    loki_enabled = bool(loki_cfg.get("enabled", False))
    elastic_enabled = bool(elastic_cfg.get("enabled", False))

    loki_url = str(loki_cfg.get("url", "http://127.0.0.1:3100/loki/api/v1/push") or "http://127.0.0.1:3100/loki/api/v1/push")
    loki_direct_push = bool(loki_cfg.get("direct_push", False))
    loki_detect_on_start = bool(loki_cfg.get("detect_on_start", True))
    loki_timeout_sec = int(loki_cfg.get("timeout_sec", 3) or 3)

    elastic_url = str(elastic_cfg.get("url", "http://127.0.0.1:9200") or "http://127.0.0.1:9200")
    elastic_bulk_url = str(elastic_cfg.get("bulk_url", "") or "").strip()
    if not elastic_bulk_url:
        elastic_bulk_url = elastic_url.rstrip("/") + "/_bulk"
    elastic_direct_push = bool(elastic_cfg.get("direct_push", False))
    elastic_detect_on_start = bool(elastic_cfg.get("detect_on_start", True))
    elastic_timeout_sec = int(elastic_cfg.get("timeout_sec", 3) or 3)
    elastic_index = str(elastic_cfg.get("index", "net-monitor-events") or "net-monitor-events")
    elastic_api_key = str(elastic_cfg.get("api_key", "") or "")
    elastic_username = str(elastic_cfg.get("username", "") or "")
    elastic_password = str(elastic_cfg.get("password", "") or "")

    if loki_enabled and loki_direct_push and loki_detect_on_start:
        loki_direct_push = _probe_loki_endpoint(loki_url, timeout_sec=loki_timeout_sec)
    if elastic_enabled and elastic_direct_push and elastic_detect_on_start:
        elastic_direct_push = _probe_elastic_endpoint(elastic_url, timeout_sec=elastic_timeout_sec)
    loki_path = paths.home / "exports" / "loki.jsonl"
    elastic_path = paths.home / "exports" / "elastic_bulk.ndjson"
    loki_buffer: List[Dict[str, Any]] = []
    elastic_buffer: List[Dict[str, Any]] = []
    protocol_tables: Dict[str, List[Dict[str, Any]]] = {"http": [], "dns": [], "smtp": []}

    target_mode, target_nets, target_ranges = _parse_targets(cfg)

    iface_cfg = cfg.get("capture", {}).get("interfaces", ["all"])
    iface = None if "all" in iface_cfg else iface_cfg[0]

    def schedule_evidence(event_ts: float, event_id: str) -> None:
        if not cfg.get("evidence", {}).get("enabled", True):
            return
        pre = int(cfg.get("evidence", {}).get("pre_seconds", 10))
        post = int(cfg.get("evidence", {}).get("post_seconds", 8))
        pending_evidence.append({
            "id": event_id,
            "t_start": event_ts - pre,
            "t_end": event_ts + post,
            "done": False,
        })

    def flush_evidence(now: float) -> None:
        for job in pending_evidence:
            if job["done"] or now < job["t_end"]:
                continue
            packets = [pkt for ts, pkt in ring if job["t_start"] <= ts <= job["t_end"]]
            if packets:
                out = paths.pcap_evidence_dir / f"evidence_{job['id']}.pcap"
                try:
                    wrpcap(str(out), packets)
                except Exception:
                    pass
            job["done"] = True

    def flush_buffers(now: float, force: bool = False) -> None:
        nonlocal last_flush, last_flush_packets

        dt = max(0.2, now - last_flush)
        packet_rate = max(0.0, float(state.total_packets - last_flush_packets) / dt)
        if adaptive_flush_enabled:
            scale = min(1.0, packet_rate / max(1.0, flush_burst_pps_hint))
            dynamic_batch = int(flush_batch_min + (flush_batch_max - flush_batch_min) * scale)
        else:
            dynamic_batch = flush_batch_min

        total_pending = (
            len(events_buffer)
            + len(ecs_buffer)
            + len(notify_buffer)
            + len(decoded_payloads_buffer)
            + len(loki_buffer)
            + len(elastic_buffer)
        )
        if not force and (now - last_flush) < flush_interval and total_pending < dynamic_batch:
            return

        if save_events_jsonl and events_buffer:
            for item in events_buffer:
                _write_jsonl(paths.events_jsonl, item)
            events_buffer.clear()

        if save_ecs_jsonl and cfg.get("ecs", {}).get("enabled", True) and ecs_buffer:
            for item in ecs_buffer:
                _write_jsonl(paths.ecs_events_jsonl, item)
            ecs_buffer.clear()

        if save_notify_jsonl and notify_buffer:
            for item in notify_buffer:
                _write_jsonl(paths.notify_jsonl, item)
            notify_buffer.clear()

        if save_decoded_payloads and decoded_payloads_buffer:
            for item in decoded_payloads_buffer:
                _write_jsonl(decoded_payloads_path, item)
            decoded_payloads_buffer.clear()

        if loki_enabled and loki_buffer:
            pushed = False
            if loki_direct_push:
                pushed = _push_loki_batch(loki_url, loki_buffer, timeout_sec=loki_timeout_sec)
            if not pushed:
                for item in loki_buffer:
                    _write_jsonl(loki_path, item)
            loki_buffer.clear()

        if elastic_enabled and elastic_buffer:
            pushed = False
            if elastic_direct_push:
                pushed = _push_elastic_bulk(
                    bulk_url=elastic_bulk_url,
                    index_name=elastic_index,
                    items=elastic_buffer,
                    timeout_sec=elastic_timeout_sec,
                    api_key=elastic_api_key,
                    username=elastic_username,
                    password=elastic_password,
                )
            if not pushed:
                for item in elastic_buffer:
                    _write_text_line(elastic_path, json.dumps({"index": {"_index": elastic_index}}, ensure_ascii=False) + "\n")
                    _write_text_line(elastic_path, json.dumps(item, ensure_ascii=False) + "\n")
            elastic_buffer.clear()

        last_flush = now
        last_flush_packets = state.total_packets

    def resolve_geo_async(ip: str, now: float) -> Dict[str, str]:
        cached = geo_cache.get(ip)
        if cached is not None and now <= float(geo_cache_expiry.get(ip, 0.0) or 0.0):
            return cached

        fut = geo_futures.get(ip)
        if fut is not None and fut.done():
            try:
                val = fut.result()
            except Exception:
                val = {"scope": "external", "country": "-", "asn": "-", "org": "-"}
            geo_cache[ip] = val
            geo_cache_expiry[ip] = now + float(geo_ttl_sec)
            geo_futures.pop(ip, None)
            return val

        if fut is None:
            geo_futures[ip] = enrichment_pool.submit(_resolve_geo_asn, ip, {}, 3)

        if cached is not None:
            return cached

        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return {
                    "scope": "local",
                    "country": "LOCAL",
                    "asn": "LOCAL",
                    "org": "local-network",
                }
        except ValueError:
            return {"scope": "unknown", "country": "-", "asn": "-", "org": "-"}
        return {"scope": "external", "country": "-", "asn": "-", "org": "-", "status": "resolving"}

    def process_packet(pkt) -> None:
        nonlocal baseline_total, last_stats, last_health, last_summary, last_process_refresh, process_future
        now = time.time()
        state.total_packets += 1
        ring.append((now, pkt))

        layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if layer is None:
            return

        src_ip = layer.src
        dst_ip = layer.dst
        if process_enabled:
            if process_future is not None and process_future.done():
                try:
                    process_map.clear()
                    process_map.update(process_future.result())
                except Exception:
                    pass
                process_future = None
            if process_future is None and (now - last_process_refresh) >= process_refresh_sec:
                process_future = enrichment_pool.submit(_collect_process_map, 3)
                last_process_refresh = now
        if not _target_match(src_ip, dst_ip, target_mode, target_nets, target_ranges):
            return
        state.target_packets += 1

        if TCP in pkt:
            sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
            l4 = "TCP"
        elif UDP in pkt:
            sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
            l4 = "UDP"
        else:
            sport, dport = 0, 0
            l4 = "OTHER"

        if not _port_allowed(sport, dport, cfg):
            return

        proto_name = _proto_name(sport, dport, l4)
        if not _protocol_allowed(proto_name, cfg):
            return
        protocol_counter.update([proto_name])
        flow_counter.update([f"{src_ip} -> {dst_ip} [{proto_name}]"])

        payload_bytes = b""
        payload_text = ""
        payload_for_tls = b""
        if Raw in pkt:
            try:
                payload_bytes = bytes(pkt[Raw].load)
            except Exception:
                payload_bytes = b""
            if payload_bytes:
                state.payload_packets += 1
                payload_text = payload_bytes.decode("utf-8", errors="replace")
                payload_for_tls = payload_bytes

        http_info = _extract_http_info(payload_text)
        dns_info = _extract_dns_info(payload_bytes, sport, dport)
        smtp_info = _extract_smtp_info(payload_text)

        if TCP in pkt and payload_bytes:
            key = (src_ip, dst_ip, sport, dport)
            stream = tcp_streams.setdefault(key, bytearray())
            stream.extend(payload_bytes)
            if len(stream) > stream_max:
                stream[:] = stream[-stream_max:]
            payload_text = stream.decode("utf-8", errors="replace")
            payload_for_tls = bytes(stream)
            http_info = _extract_http_info(payload_text)
            smtp_info = _extract_smtp_info(payload_text)

        if ignored_by_exception(src_ip, dst_ip, payload_text, exceptions):
            return

        matches = match_patterns(payload_text, rules)

        query_hits = []
        lines = payload_text.splitlines()
        if lines and lines[0].startswith(HTTP_METHODS):
            parts = lines[0].split(" ")
            if len(parts) >= 2:
                query = urlsplit(parts[1]).query
                for k, v in parse_qsl(query, keep_blank_values=True):
                    lk = k.lower()
                    if lk in ("token", "api_key", "password", "access_token", "refresh_token") and v:
                        query_hits.append({"rule_name": f"query:{k}", "severity": "high", "value_redacted": v[:4] + "..."})

        entropy_hits = []
        seen = set()
        for token in TOKEN_CANDIDATE.findall(payload_text):
            if token in seen:
                continue
            seen.add(token)
            if token.lower().startswith(("http", "mozilla", "accept", "content")):
                continue
            if _shannon_entropy(token) >= 4.2:
                entropy_hits.append({"rule_name": "entropy_token", "severity": "medium", "value_redacted": token[:4] + "..."})

        tls_cfg = cfg.get("tls_audit", {})
        tls_info: Dict[str, Any] = {}
        if tls_cfg.get("enabled", True) and payload_for_tls:
            tls_info = parse_tls_metadata(payload_for_tls)

        issues: List[Dict[str, Any]] = []
        for p in (sport, dport):
            if p in LEGACY_PORTS:
                title, sev = LEGACY_PORTS[p]
                issues.append({
                    "severity": sev,
                    "title": title,
                    "evidence": f"port {p}",
                    "recommendation": "Move traffic to encrypted protocol / segmented VPN",
                })

        tls_ver = tls_info.get("record_version") or tls_info.get("server_version") or tls_info.get("client_version")
        if tls_ver in ("SSLv3", "TLS1.0", "TLS1.1"):
            issues.append({
                "severity": "high",
                "title": "Weak TLS version",
                "evidence": tls_ver,
                "recommendation": "Allow only TLS1.2+ and prefer TLS1.3",
            })

        if tls_cfg.get("enabled", True) and tls_info.get("cipher_quality") == "weak":
            issues.append({
                "severity": "high",
                "title": "Weak TLS cipher suite",
                "evidence": tls_info.get("cipher_suite_name", "unknown"),
                "recommendation": "Disable weak ciphers and prefer AEAD suites (GCM/CHACHA20)",
            })

        weak_sig_algs = tls_info.get("weak_signature_algorithms", [])
        if tls_cfg.get("enabled", True) and weak_sig_algs:
            issues.append({
                "severity": "high",
                "title": "Weak TLS signature/hash algorithms",
                "evidence": ", ".join(weak_sig_algs[:5]),
                "recommendation": "Disable MD5/SHA1 signature algorithms and require SHA256+ / modern suites",
            })

        days_to_expiry = tls_info.get("leaf_days_to_expiry")
        warn_expiry_days = int(tls_cfg.get("warn_expiry_days", 14))
        fail_on_expired = bool(tls_cfg.get("fail_on_expired", True))
        if tls_cfg.get("enabled", True) and isinstance(days_to_expiry, int) and days_to_expiry < 0 and fail_on_expired:
            issues.append({
                "severity": "critical",
                "title": "Expired TLS certificate detected",
                "evidence": f"leaf_days_to_expiry={days_to_expiry}",
                "recommendation": "Rotate certificate immediately and validate chain trust",
            })
        elif tls_cfg.get("enabled", True) and isinstance(days_to_expiry, int) and days_to_expiry <= warn_expiry_days:
            issues.append({
                "severity": "medium",
                "title": "TLS certificate close to expiry",
                "evidence": f"leaf_days_to_expiry={days_to_expiry}",
                "recommendation": "Renew certificate proactively and monitor cert lifetime",
            })

        if "authorization:" in payload_text.lower() and 443 not in {sport, dport}:
            issues.append({
                "severity": "critical",
                "title": "Auth header outside TLS",
                "evidence": "Authorization detected on non-TLS path",
                "recommendation": "Enforce HTTPS for all auth endpoints",
            })

        all_hits = [
            {"rule_name": m.rule_name, "severity": m.severity, "value_redacted": m.value_redacted} for m in matches
        ] + query_hits + entropy_hits

        max_hit_sev = min_severity(matches) if matches else None
        max_hit_sev = max_hit_sev or (query_hits[0]["severity"] if query_hits else None) or (entropy_hits[0]["severity"] if entropy_hits else None)

        anomaly = None
        if cfg.get("baseline", {}).get("enabled", True):
            if baseline_total >= int(cfg.get("baseline", {}).get("learn_packets", 2000)):
                base_count = max(1, int(baseline_proto.get(proto_name, 0)))
                ratio = protocol_counter[proto_name] / base_count
                if ratio >= float(cfg.get("baseline", {}).get("anomaly_threshold_ratio", 5.0)):
                    anomaly = {
                        "severity": "medium",
                        "title": "Protocol distribution anomaly",
                        "evidence": f"{proto_name} ratio={ratio:.2f}",
                        "recommendation": "Review service changes or suspicious scanning bursts",
                    }
                    issues.append(anomaly)
            else:
                baseline_proto[proto_name] += 1
                baseline_total += 1

        behavior_anomaly = None
        if behavior_enabled:
            dq = dst_activity.setdefault(dst_ip, deque())
            dq.append(now)
            while dq and now - dq[0] > behavior_window_sec:
                dq.popleft()
            if len(dq) >= behavior_burst_threshold:
                behavior_anomaly = {
                    "severity": "medium",
                    "title": "Destination burst anomaly",
                    "evidence": f"dst={dst_ip} hits={len(dq)} window={behavior_window_sec}s",
                    "recommendation": "Validate scanner activity, possible flood or exfiltration pattern",
                }
                issues.append(behavior_anomaly)
                behavior_counter.update(["dst_burst_anomaly"])

        if not all_hits and not issues:
            if now - last_stats >= stats_interval:
                print(f"[stats] total={state.total_packets} target={state.target_packets} payload={state.payload_packets} alerts={state.alerts_emitted} suppressed={state.alerts_suppressed} dropped={state.dropped_packets}")
                last_stats = now
            if now - last_health >= health_interval:
                _touch_health(paths, state, protocol_counter, issue_severity_counter)
                last_health = now
            flush_buffers(now)
            flush_evidence(now)
            return

        highest = "low"
        for sev in [x.get("severity", "low") for x in all_hits] + [x.get("severity", "low") for x in issues]:
            if {"low": 1, "medium": 2, "high": 3, "critical": 4}[sev] > {"low": 1, "medium": 2, "high": 3, "critical": 4}[highest]:
                highest = sev

        if not severity_allowed(highest, min_sev):
            return

        fp = f"{src_ip}|{dst_ip}|{sport}|{dport}|{proto_name}|{highest}|{len(all_hits)}|{len(issues)}"

        if low_sampling_enabled and highest == "low":
            dt = max(0.2, now - last_flush)
            current_pps = max(0.0, float(state.total_packets - last_flush_packets) / dt)
            if current_pps >= low_sampling_burst_pps and not _sample_by_fingerprint(fp, low_sampling_keep_ratio):
                state.dropped_packets += 1
                behavior_counter.update(["low_severity_sampled"])
                return

        rec = dedupe.setdefault(fp, {"count": 0.0, "last_emit": 0.0})
        rec["count"] += 1.0

        if int(rec["count"]) < min_repeat:
            return
        if now - rec["last_emit"] < dedupe_window:
            state.alerts_suppressed += 1
            return

        rec["last_emit"] = now
        state.alerts_emitted += 1

        issue_severity_counter.update([i["severity"] for i in issues])
        for i in issues:
            key = f"{i['severity']}|{i['title']}|{src_ip}|{dst_ip}|{dport}"
            if key not in issue_registry:
                issue_registry[key] = {
                    "severity": i["severity"],
                    "title": i["title"],
                    "evidence": i["evidence"],
                    "recommendation": i["recommendation"],
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dport,
                    "seen_count": 1,
                    "last_seen": int(now),
                }
                state.risk_score += SEVERITY_WEIGHTS.get(i["severity"], 1)
            else:
                issue_registry[key]["seen_count"] += 1
                issue_registry[key]["last_seen"] = int(now)

        event_id = f"{int(now)}_{state.alerts_emitted}"

        has_behavior_anomaly = behavior_anomaly is not None
        mapped_attack = _map_attack_techniques(issues, http_info, dns_info, has_behavior_anomaly)
        event_risk_score = _event_risk_score(highest, issues, all_hits, has_behavior_anomaly)
        device_profile = _infer_device_profile(proto_name, sport, dport, http_info)

        tls_fp_src = "|".join([
            str(tls_info.get("client_version", "")),
            str(tls_info.get("server_version", "")),
            str(tls_info.get("record_version", "")),
            str(tls_info.get("cipher_suite_name", "")),
            str(tls_info.get("sni", "")),
        ])
        http_fp_src = "|".join([
            str(http_info.get("method", "")),
            str(http_info.get("host", "")),
            str(http_info.get("user_agent", ""))[:120],
        ])
        fingerprints = {
            "tls_client": hashlib.sha1(tls_fp_src.encode("utf-8", errors="ignore")).hexdigest()[:24] if tls_fp_src.strip("|") else "",
            "http_client": hashlib.sha1(http_fp_src.encode("utf-8", errors="ignore")).hexdigest()[:24] if http_fp_src.strip("|") else "",
        }

        event = {
            "event_id": event_id,
            "timestamp": int(now),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto_name,
            "severity": highest,
            "matches": all_hits,
            "issues": issues,
            "tls": tls_info,
            "http": http_info,
            "dns": dns_info,
            "smtp": smtp_info,
            "process": process_map.get((src_ip, sport, dst_ip, dport), {}),
            "geo": {
                "src": resolve_geo_async(src_ip, now) if geo_enabled else {},
                "dst": resolve_geo_async(dst_ip, now) if geo_enabled else {},
            },
            "risk_score": event_risk_score,
            "attack": mapped_attack,
            "device": device_profile,
            "fingerprints": fingerprints,
            "payload_preview": payload_text[:500] if payload_text else None,
        }

        for item in mapped_attack:
            tid = str(item.get("id", "")).strip()
            if tid:
                attack_counter.update([tid])

        for ip_addr in {src_ip, dst_ip}:
            rec_asset = asset_inventory.setdefault(
                ip_addr,
                {
                    "ip": ip_addr,
                    "first_seen": int(now),
                    "last_seen": int(now),
                    "hits": 0,
                    "device_type": "unknown",
                },
            )
            rec_asset["last_seen"] = int(now)
            rec_asset["hits"] = int(rec_asset.get("hits", 0) or 0) + 1
            if rec_asset.get("device_type") == "unknown" and device_profile.get("type") not in (None, "", "unknown"):
                rec_asset["device_type"] = str(device_profile.get("type"))

        if http_info:
            protocol_tables["http"].append({
                "timestamp": int(now),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "method": http_info.get("method", ""),
                "path": http_info.get("path", ""),
                "host": http_info.get("host", ""),
            })
            protocol_tables["http"] = protocol_tables["http"][-300:]
        if dns_info:
            protocol_tables["dns"].append({
                "timestamp": int(now),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "query": dns_info.get("query", ""),
            })
            protocol_tables["dns"] = protocol_tables["dns"][-300:]
        if smtp_info:
            protocol_tables["smtp"].append({
                "timestamp": int(now),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "command": smtp_info.get("command", ""),
                "mail_from": smtp_info.get("mail_from", ""),
                "rcpt_to": smtp_info.get("rcpt_to", ""),
            })
            protocol_tables["smtp"] = protocol_tables["smtp"][-300:]
        if severity_allowed(highest, min_severity_to_save):
            if save_events_jsonl:
                events_buffer.append(event)
            if save_ecs_jsonl and cfg.get("ecs", {}).get("enabled", True):
                ecs_event = _to_ecs_event(event)
                ecs_buffer.append(ecs_event)
                if loki_enabled:
                    loki_buffer.append({
                        "ts": int(now),
                        "labels": {
                            "app": "net-monitor",
                            "severity": highest,
                            "protocol": str(proto_name).lower(),
                        },
                        "line": json.dumps({
                            "event_id": event_id,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "severity": highest,
                            "title": (issues[0].get("title") if issues else "event"),
                        }, ensure_ascii=False),
                    })
                if elastic_enabled:
                    elastic_buffer.append(ecs_event)
            if save_decoded_payloads and payload_text.strip():
                decoded_payloads_buffer.append({
                    "timestamp": int(now),
                    "event_id": event_id,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": sport,
                    "dst_port": dport,
                    "protocol": proto_name,
                    "severity": highest,
                    "decoded_payload": payload_text[:2000],
                })

        notify_cfg = cfg.get("notifications", {})
        if (
            notify_cfg.get("enabled", True)
            and save_notify_jsonl
            and severity_allowed(highest, notify_cfg.get("min_severity", "high"))
            and severity_allowed(highest, min_severity_to_save)
        ):
            notify_buffer.append({
                "timestamp": int(now),
                "event_id": event_id,
                "title": f"[{highest.upper()}] {proto_name} security alert",
                "message": f"{src_ip}:{sport} -> {dst_ip}:{dport}",
                "severity": highest,
            })

        schedule_evidence(now, event_id)

        if now - last_stats >= stats_interval:
            print(f"[stats] total={state.total_packets} target={state.target_packets} payload={state.payload_packets} alerts={state.alerts_emitted} suppressed={state.alerts_suppressed} dropped={state.dropped_packets}")
            last_stats = now

        if now - last_health >= health_interval:
            _touch_health(paths, state, protocol_counter, issue_severity_counter)
            last_health = now

        if now - last_summary >= health_interval:
            _store_summary(
                paths,
                state,
                protocol_counter,
                issue_registry,
                protocol_tables,
                flow_counter,
                behavior_counter,
                attack_counter,
                asset_inventory,
            )
            last_summary = now

        flush_buffers(now)
        flush_evidence(now)

    print("[net-monitor] starting daemon")
    print(f"[net-monitor] config: {config_path or str(paths.config)}")
    print(f"[net-monitor] storage: {paths.home}")

    try:
        sniff(iface=iface, prn=process_packet, store=False)
    finally:
        try:
            enrichment_pool.shutdown(wait=False)
        except Exception:
            pass
        flush_buffers(time.time(), force=True)
        _save_baseline(paths, {
            "saved_at": int(time.time()),
            "total_packets": baseline_total,
            "protocol_inventory": dict(baseline_proto),
        })
        _store_summary(
            paths,
            state,
            protocol_counter,
            issue_registry,
            protocol_tables,
            flow_counter,
            behavior_counter,
            attack_counter,
            asset_inventory,
        )
        _touch_health(paths, state, protocol_counter, issue_severity_counter)

    if once:
        return


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="net-monitor passive daemon")
    p.add_argument("--config", default=None, help="Path to config.yaml")
    p.add_argument("--home", default=None, help="Path to net-monitor data home (default: ~/.net-monitor)")
    p.add_argument("--once", action="store_true", help="Run one session and exit")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()
    run_daemon(config_path=args.config, once=args.once, home_path=args.home)


if __name__ == "__main__":
    main()
