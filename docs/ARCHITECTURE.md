# Architecture

## Components

1. `net_monitor.daemon`
   - packet capture;
   - target/port/protocol filtering;
   - TCP stream reassembly;
   - rule engine checks;
   - TLS weak-version/SNI/JA3-like extraction;
   - baseline + anomaly checks;
   - ring-buffer evidence writer;
   - events/summary/health persistence.

2. `net_monitor.tray`
   - Ubuntu AppIndicator icon;
   - status panel + settings editor;
   - popup notifications from `notify_queue.jsonl`;
   - writes config back to `~/.net-monitor/config.yaml`.

3. Storage `~/.net-monitor`
   - source of truth for runtime state and configuration.

## Data flow

1. daemon sniffs packets;
2. packet -> filters -> stream aggregator -> detection pipeline;
3. findings/issues -> `events.jsonl`;
4. high severity -> `notify_queue.jsonl`;
5. health summary -> `health.json`, `summary.json`;
6. tray reads health + notify queue and renders UI/notifications.

## Security model

- passive only;
- no packet injection;
- no exploit modules;
- local storage in user home;
- secrets are stored in redacted form in events.
