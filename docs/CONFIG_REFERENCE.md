# Config reference (`~/.net-monitor/config.yaml`)

## capture.interfaces

- `all`
- one interface: `eth0`
- multiple: `["eth0", "wlan0"]`

## capture.targets

- `mode: all`
- `mode: ips` + `ips: ["192.168.1.20", "192.168.1.21"]`
- `mode: subnets` + `subnets: ["10.42.0.0/16"]`
- `mode: ranges` + `ranges: ["192.168.1.10-192.168.1.50"]`
- `mode: mixed` + combined lists

## capture.ports

- `mode: all`
- `mode: list` + `list: [80, 443, 8080]`
- `mode: range` + `ranges: ["1000-2000"]`

## capture.protocols

Examples:

- `["all"]`
- `["tcp", "udp", "http", "tls", "dns"]`

## rules

- `profile`: strict/balanced/lenient
- `min_severity`: low/medium/high/critical
- `dedupe_window_sec`
- `min_repeat`

## baseline

- `enabled`
- `learn_packets`
- `anomaly_threshold_ratio`

## evidence

- `enabled`
- `pre_seconds`
- `post_seconds`
- `max_ring_packets`

## notifications

- `enabled`
- `min_severity`

## ecs

- `enabled` — запис ECS-подій у `~/.net-monitor/events_ecs.jsonl`

## tls_audit

- `enabled`
- `warn_expiry_days`
- `fail_on_expired`

## runtime

- `stats_interval_sec`
- `health_interval_sec`
- `tcp_stream_max_bytes`
