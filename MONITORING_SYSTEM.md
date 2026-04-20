# Monitoring System Documentation

## 1. Purpose

`net-monitor` is a passive network monitoring system for local/lab environments.
It captures traffic, detects suspicious patterns, enriches events with TLS posture data,
exports ECS-compatible records, and provides a tray UX for operations.

## 2. High-Level Architecture

Main components:

1. `net_monitor/daemon.py`
   - packet capture and parsing;
   - protocol normalization;
   - rule and anomaly analysis;
   - issue severity calculation;
   - event/health/summary persistence;
   - notification queue production.

2. `net_monitor/tray.py`
   - AppIndicator tray icon and menu;
   - monitoring and settings window;
   - packets table with filters and details;
   - TLS posture view;
   - popup notifications consumer;
   - IP address list and on-demand scan dialog with progress/cancel.

3. `net_monitor/ip_scan_backend.py`
   - asynchronous scan execution in background thread;
   - command construction by profile (`quick`, `dns`, `full`);
   - scan result normalization;
   - scan history persistence into JSONL.

4. `install.sh`
   - system dependency setup;
   - virtualenv provisioning;
   - systemd unit rendering and enablement;
   - diagnostics (`--status`) and logs.

## 3. Runtime Data Layout

Default runtime home: `~/.net-monitor`

Key files:

- `config.yaml` — runtime configuration.
- `patterns.yaml` — detection patterns.
- `events.jsonl` — raw internal events.
- `events_ecs.jsonl` — ECS export for SIEM/ELK.
- `decoded_payloads.jsonl` — decoded/plain payload excerpts saved separately.
- `exports/loki.jsonl` — Loki-ready JSONL export (optional).
- `exports/elastic_bulk.ndjson` — Elastic bulk NDJSON export (optional).
- `summary.json` — aggregated state/scores.
- `health.json` — heartbeat and packet counters.
- `notify_queue.jsonl` — daemon->tray alert queue.
- `ui_history.json` — tray input history for targets/ports.
- `scan_history.jsonl` — IP scan execution history.

## 4. Event and Severity Model

Typical event fields:

- `timestamp`, `event_id`
- `src_ip`, `dst_ip`, `src_port`, `dst_port`
- `protocol`
- `severity` (`low|medium|high|critical`)
- `issues[]`
- `tls{}`

Severity ordering used by tray and notification filters:

- `low` < `medium` < `high` < `critical`

## 5. Tray UX Behavior

### 5.1 Menu actions

- `Open Monitor` — opens the monitor tab.
- `Settings` — opens the settings tab.
- `Monitoring Enabled` — starts/stops daemon service.
- `Popup Notifications` — globally enables/disables popups.
- `Restart Daemon`
- `Quit`

### 5.2 Window lifecycle (important)

The main window is hidden on close (`delete-event`) instead of destroyed.
This prevents the "empty window on second open" issue.

### 5.3 Tabs

- `Monitor`: live status and event log.
- `Packets`: table + filters (`severity`, `protocol`, `src`, `dst`, text search), with selection preservation during auto-refresh.
- `TLS posture`: scores, problematic hosts, cert expiry data.
- `Settings`: capture filters, notification min severity, tray packet count display, persistence controls.
- `Advanced`: patterns editor + rules/runtime/tls/service controls.
- `Geo/ASN`: destination geolocation/ASN and correlated process info.
- `HTTP`, `DNS`, `SMTP`: parsed protocol tables.
- `Flows`: realtime top flow edges + behavior anomaly counters.

## 6. Notification Control

Two levels are applied:

1. Daemon queue production (`notifications.enabled` and `notifications.min_severity`).
2. Tray popup display control:
   - menu toggle `Popup Notifications` (`notifications.enabled`),
   - local severity gate with `Notification min severity`.

Default minimum severity: `critical`.

## 7. Tray Indicator State Mapping

When daemon is disabled:

- icon state: `off` (`process-stop`, gray).

When daemon is active, indicator icon depends on highest detected severity:

- `critical` -> red/error icon,
- `high` -> orange/warning icon,
- `medium` -> info/yellow-like icon,
- `low` or no alerts -> normal/green-like icon.

Label behavior:

- label mode is configurable: `risk|total|critical|total+critical`;
- optional packet count display (`tray.show_packet_count`) adds `P:<total>`.

## 8. IP Address Scan Window

From `Monitor` tab, button `IP addresses and scan` opens a dedicated window:

- source list: observed `src_ip` + `dst_ip` from event cache;
- source list filter modes:
  - `all`,
  - `local only`,
  - `external only`,
  - `with alerts`;
- target field supports both dropdown selection (observed IPs) and manual input;
- selected IP can be applied explicitly via `Use selected IP` to avoid value reset while refreshing list;
- scan profile selection:
  - `quick` -> fast port scan (`nmap -F -Pn`),
  - `dns` -> DNS/name lookups (`dig`, `host`),
  - `port-top100` / `port-top1000` -> top-port scans,
  - `service-fingerprint` -> deep version fingerprint (`nmap -sV --version-all`),
  - `tls-endpoint` -> TLS scripts (`ssl-cert`, `ssl-enum-ciphers`),
  - `dns-hygiene` -> DNSSEC/trace checks,
  - `url-scan` -> HTTP headers (+TLS probe for https),
  - `full` -> detailed scan (`nmap -sV -sC -O -Pn`);
- for `full`, operator can manually set:
  - ports (`-p ...`),
  - scripts (`--script ...`);
- output is displayed in the same dialog.

Execution model:

- scan starts asynchronously in backend thread;
- tray UI remains responsive during long `full` scans;
- progress bar and elapsed time are shown while scan is running;
- timeout is profile-aware (no single hard 120s timeout for all profiles);
- operator can cancel active scan from UI;
- active/final command is shown in scan output (`Running: ...` and `command=...` in result header);
- upon completion, backend posts status/output back to tray UI;
- result is appended to `scan_history.jsonl` and reflected in history table.

Notes:

- Requires scanner tools available in the system (`nmap`, `dnsutils` for `dig`/`host`).
- Full scans use `pkexec` to request password when elevated privileges are needed.
- If privileged full scan still fails with `Operation not permitted`, backend falls back to non-`-O` variant and returns combined output.

## 9. Persistence and Flush Model

Event-like outputs are buffered and flushed by interval (default `60s`):

- `events.jsonl`
- `events_ecs.jsonl`
- `notify_queue.jsonl`
- `decoded_payloads.jsonl`

Storage controls live under `storage` in `config.yaml`:

- `flush_interval_sec`
- `save_events_jsonl`
- `save_ecs_jsonl`
- `save_notify_jsonl`
- `save_decoded_payloads`
- `min_severity_to_save`

This reduces disk churn and improves tray responsiveness under load.

## 10. Enrichment, Behavior and Exports

Daemon enriches events with:

- `geo.src` / `geo.dst` (country/asn/org, best-effort);
- `process` correlation (`pid`, `name`, transport) via `ss -tunp` snapshot cache;
- per-protocol parsed rows for `http`, `dns`, `smtp` in summary.

Behavior controls:

- `behavior.enabled`
- `behavior.dst_burst_window_sec`
- `behavior.dst_burst_threshold`

Export controls:

- `exports.loki.enabled` -> writes `exports/loki.jsonl`
- `exports.elastic.enabled` -> writes `exports/elastic_bulk.ndjson`

Phase 2 direct push:

- Loki: `exports.loki.direct_push`, `exports.loki.url`, `exports.loki.detect_on_start`, `exports.loki.timeout_sec`
- Elastic: `exports.elastic.direct_push`, `exports.elastic.url`, `exports.elastic.bulk_url`, `exports.elastic.index`, `exports.elastic.detect_on_start`, `exports.elastic.timeout_sec`

If direct push is enabled but endpoint is unavailable, daemon falls back to file export.

## 11. Advanced Settings in Tray

`Advanced` tab exposes:

- direct `patterns.yaml` editing (`Reload patterns`, `Save patterns`);
- `rules.profile`, `rules.min_severity`, `rules.dedupe_window_sec`, `rules.min_repeat`;
- `runtime.stats_interval_sec`, `runtime.health_interval_sec`;
- `tls_audit.warn_expiry_days`;
- `services.daemon_unit`, `services.tray_unit`;
- export controls for Loki/Elastic direct push + endpoint URLs + index;
- `Auto configure exports` button that probes endpoints and only enables direct push when backend is reachable.

## 12. UI Refresh Stability

Auto-refresh views preserve vertical scroll position to avoid jumpy scrolling:

- `Packets`
- `Geo/ASN`
- `HTTP`, `DNS`, `SMTP`
- `Flows`

## 13. Dashboards

Repository includes starter dashboards:

- Grafana: `dashboards/grafana/net-monitor-overview.json`
- Kibana: `dashboards/kibana/net-monitor.ndjson`

## 14. Systemd Services

- `net-monitor.service` (system/root): daemon capture/analysis.
- `net-monitor-tray.service` (user): GUI tray process.

Production mode uses both simultaneously.

## 15. Installer Diagnostics

`sudo ./install.sh --status` provides:

- service states for daemon and tray;
- recent `journalctl` excerpts;
- smoke checks for GUI/runtime imports;
- quick diagnosis with recovery hints.

## 16. Security and Scope

- Passive monitoring only (no active exploitation).
- Data is intended for local defensive analysis.
- Use active scan profiles only when authorized in the target environment.
