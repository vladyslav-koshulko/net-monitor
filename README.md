# net-monitor

Пасивна утиліта аудиту безпеки пакетного трафіку для локального стенду.

## Що вміє

- пасивний capture трафіку (без активних атак);
- TCP reassembly для точнішого детекту секретів по сегментах;
- deep TLS audit (версія, SNI, JA3/JA4-like, cipher quality, cert chain/expiry);
- rule engine через `~/.net-monitor/patterns.yaml`;
- baseline + anomaly detection по протоколах;
- ring buffer + evidence `.pcap` (до/після алерту);
- health/watchdog (heartbeat, packet metrics, self-checks);
- ECS export для ELK/SIEM у `~/.net-monitor/events_ecs.jsonl`;
- tray-іконка у верхній панелі Ubuntu (AppIndicator);
- popup-сповіщення з керуванням через меню tray та порогом критичності.

## Директорії та дані

Усі runtime-дані зберігаються в `~/.net-monitor`:

- `config.yaml`
- `patterns.yaml`
- `events.jsonl`
- `events_ecs.jsonl`
- `decoded_payloads.jsonl`
- `exports/loki.jsonl` (якщо увімкнено)
- `exports/elastic_bulk.ndjson` (якщо увімкнено)
- `summary.json`
- `baseline.json`
- `health.json`
- `notify_queue.jsonl`
- `pcap/evidence/*.pcap`

## Встановлення

```bash
cd net-monitor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Локальний запуск

```bash
PYTHONPATH=. python3 -m net_monitor monitor
```

```bash
PYTHONPATH=. python3 -m net_monitor tray
```

```bash
PYTHONPATH=. python3 -m net_monitor full
```

`full` — dev-режим для запуску daemon + tray з одного терміналу.

## Авто-інсталятор

```bash
sudo ./install.sh
```

```bash
sudo ./install.sh --reinstall
```

```bash
sudo ./install.sh --status
```

Скрипт:

- ставить потрібні OS/Python залежності;
- створює/оновлює локальне `.venv` (з `--system-site-packages`) і ставить Python-залежності туди;
- рендерить systemd unit-файли з правильними шляхами;
- вмикає daemon (`system`) + tray (`user`) сервіси;
- готує `~/.net-monitor`.

Режими:

- `--reinstall` — повністю перебудувати `.venv` і перевстановити python-залежності;
- `--status` — діагностика сервісів і стану файлів без внесення змін.

Діагностика (`--status`) додатково перевіряє:

- імпорт `gi` саме через `net-monitor/.venv/bin/python`;
- швидкий smoke-check `tray` модуля;
- останні помилки `journalctl` для daemon/tray;
- короткий діагноз стану сервісів;
- підказки автофіксу при проблемах із user DBus/systemd.

Якщо під час `sudo ./install.sh` бачиш помилку `Failed to connect to bus` для tray-сервісу,
це означає, що в момент запуску немає активної user GUI/DBus сесії.
Увійди в графічну сесію потрібного користувача і виконай:

```bash
systemctl --user daemon-reload
systemctl --user enable --now net-monitor-tray.service
```

## Systemd (daemon)

```bash
sudo cp systemd/net-monitor.service /etc/systemd/system/net-monitor.service
sudo systemctl daemon-reload
sudo systemctl enable --now net-monitor.service
sudo systemctl status net-monitor.service
```

## Systemd (tray, user)

```bash
mkdir -p ~/.config/systemd/user
cp systemd/net-monitor-tray.service ~/.config/systemd/user/net-monitor-tray.service
systemctl --user daemon-reload
systemctl --user enable --now net-monitor-tray.service
systemctl --user status net-monitor-tray.service
```

Повний production-режим = одночасно обидва сервіси:

- `net-monitor.service` (збір/аналіз в background)
- `net-monitor-tray.service` (іконка, налаштування, popup, статистика)

## Ubuntu верхня панель

Встанови пакети:

```bash
sudo apt update
sudo apt install -y python3-gi gir1.2-gtk-3.0 gir1.2-ayatanaappindicator3-0.1 libnotify-bin gnome-shell-extension-appindicator
```

Після цього tray-іконка буде у верхній панелі.

## Налаштування через tray

По кліку на іконку відкривається вікно:

- статистика моніторингу;
- `Open Monitor` відкриває саме вкладку моніторингу (не налаштування);
- окрема вкладка `Packets` для списку подій/пакетів та детального перегляду;
- у `Packets` є фільтри: `severity`, `protocol`, `src`, `dst` та повнотекстовий пошук;
- у `Packets` збереження вибраного рядка стабільне при auto-refresh (вибір не "злітає");
- кнопка налаштувань (інтерфейси, IP/підмережі/діапазони, порти, протоколи);
- `Settings` з меню відкриває вкладку налаштувань;
- в меню іконки є тумблер `Monitoring Enabled` (start/stop daemon);
- в меню іконки є перемикач `Popup Notifications` (on/off);
- вікно не знищується при закритті, тому повторне `Open Monitor`/`Settings` більше не відкриває порожнє вікно;
- вкладка `TLS posture` (top проблемні хости, cert expiry table, TLS/Cipher scores);
- вкладка `Geo/ASN`: країна/ASN/організація для destination IP + кореляція `process:pid`;
- вкладки `HTTP`, `DNS`, `SMTP`: окремі protocol tables;
- вкладка `Flows`: realtime top edges та аномалії поведінки;
- у `TLS posture` можна виділяти/копіювати текст, auto-refresh не перезаписує поле під час фокусу;
- збереження в `~/.net-monitor/config.yaml`.

UI-елементи налаштувань:

- інтерфейси: випадаючий список + `all` + ручне введення;
- targets: випадаючі підказки + `all` + ручне введення;
- protocols: випадаючий список + `all` + ручне введення;
- ports: ручне введення + історія попередніх значень у підказках;
- `Notification min severity`: `low|medium|high|critical` (за замовчуванням `critical`);
- `Show packet count near icon`: показує/ховає `P:<packets_total>` біля іконки;
- `Tray indicator label mode`: `risk|total|critical|total+critical`;
- `Persist interval (sec)`: інтервал flush для JSONL файлів (типово 60с);
- вибір, що зберігати: `events`, `ecs`, `notify`, `decoded_payloads`;
- `Min severity to save`: фільтр мінімальної критичності для запису у файли.

Стан іконки в панелі:

- daemon `off` -> сірий індикатор (`process-stop`);
- `critical` -> червоний;
- `high` -> помаранчевий;
- `medium` -> жовтий/інформаційний;
- `low`/інше -> зелений/нормальний стан.

У вкладці `Monitor` є кнопка `IP addresses and scan`:

- відкриває окреме вікно зі списком побачених IP (src/dst);
- по кліку IP підставляється в поле цілі;
- фільтрація списку IP: `all`, `local only`, `external only`, `with alerts`;
- profiles сканування: `quick`, `dns`, `full`;
- додаткові профілі: `port-top100`, `port-top1000`, `service-fingerprint`, `tls-endpoint`, `dns-hygiene`, `url-scan`;
- для `full` використовується `pkexec` (запит пароля) для OS fingerprint/scans, що потребують root;
- якщо навіть після введення пароля є `Operation not permitted`, виконується fallback без `-O` (без OS fingerprint), щоб скан не падав повністю;
- для `full` доступне ручне налаштування `ports` і `scripts`;
- сканування запускається асинхронно (UI не блокується);
- у вікні скану є `Progress`, live-статус, elapsed time та кнопка `Cancel scan`;
- таймаути сканів профільні (довгі профілі, включно з `full`, не обриваються через загальний 120s timeout);
- для кожного скану в UI показується фактична команда (`Running: ...`, а також `command=...` у фінальному результаті);
- історія сканів (час, ціль, профіль, статус) зберігається в `~/.net-monitor/scan_history.jsonl` і показується в UI;
- поле цілі скану: dropdown з побачених IP + можливість ручного вводу;
- результат сканування показується в тому ж вікні.

Продуктивність/UI:

- tray status refresh працює частіше (кожні ~500мс) для більш "живого" лічильника;
- індикатор і статистика оновлюються практично в realtime без блокування UI.
- виправлено "стрибки" scroll при auto-refresh: позиція прокрутки зберігається у `Packets`, `Geo/ASN`, `HTTP`, `DNS`, `SMTP`, `Flows`.

## Advanced Settings

Додано вкладку `Advanced` у tray UI:

- редагування `~/.net-monitor/patterns.yaml` прямо з UI (`Reload patterns`, `Save patterns`);
- розширені параметри правил: `profile`, `min_severity`, `dedupe_window_sec`, `min_repeat`;
- runtime-параметри: `stats_interval_sec`, `health_interval_sec`;
- TLS параметр: `warn_expiry_days`;
- service-параметри: `services.daemon_unit`, `services.tray_unit`.

## Enrichment / Behavior / Exports

Нові секції в `config.yaml`:

- `enrichment.geo_asn`, `enrichment.process_correlation`, `enrichment.process_refresh_sec`;
- `behavior.enabled`, `behavior.dst_burst_window_sec`, `behavior.dst_burst_threshold`;
- `exports.loki.enabled`, `exports.elastic.enabled`.

### Phase 2: direct push + auto-setup

Додано прямий push у бекенди, якщо вони доступні:

- `exports.loki.direct_push`, `exports.loki.url`, `exports.loki.detect_on_start`, `exports.loki.timeout_sec`;
- `exports.elastic.direct_push`, `exports.elastic.url`, `exports.elastic.bulk_url`, `exports.elastic.index`, `exports.elastic.detect_on_start`, `exports.elastic.timeout_sec`.

У вкладці `Advanced` додані:

- перемикачі `Loki direct push` / `Elastic direct push`;
- поля URL для Loki/Elastic + index для Elastic;
- кнопка `Auto configure exports` (перевіряє доступність endpoint і автоматично вмикає push тільки коли endpoint піднятий).

Якщо прямий push недоступний, daemon робить fallback у файловий експорт:

- `~/.net-monitor/exports/loki.jsonl`
- `~/.net-monitor/exports/elastic_bulk.ndjson`

Готові dashboard-файли у репозиторії:

- `dashboards/grafana/net-monitor-overview.json`
- `dashboards/kibana/net-monitor.ndjson`

Примітки:

- Geo/ASN працює best-effort (локальні IP -> `LOCAL`, зовнішні через `whois`, якщо доступно);
- process correlation використовує `ss -tunp` (може вимагати додаткові права для повних даних);
- експорт у Loki/Elastic підтримує direct push; якщо endpoint недоступний, використовується fallback у файли (`jsonl/ndjson`).

## Оновлення до нової версії

1. Онови код проєкту (pull/checkout потрібного коміту).
2. Перевстанови python-залежності у `venv`:

```bash
cd net-monitor
source .venv/bin/activate
pip install -r requirements.txt
```

3. Перевір синтаксис модулів:

```bash
python3 -m py_compile net_monitor/tray.py net_monitor/ip_scan_backend.py net_monitor/daemon.py
```

4. Перезапусти сервіси:

```bash
sudo systemctl restart net-monitor.service
systemctl --user restart net-monitor-tray.service
```

5. Відкрий tray -> `Settings`/`Advanced` і збережи конфіг, щоб нові поля записались у `~/.net-monitor/config.yaml`.

## Детальна документація

Розширений опис архітектури, форматів даних, tray UX і сценаріїв діагностики дивись у файлі:

- `MONITORING_SYSTEM.md`

## Обмеження

- утиліта працює тільки в пасивному режимі;
- TLS аудит робиться пасивно на основі доступного packet/stream матеріалу (best-effort);
- для максимальної точності бажано запускати daemon з root-правами.

## venv чи без нього

Рекомендовано: через локальний `.venv` (як робить `install.sh`).

- ізоляція python-залежностей (`scapy`, `cryptography`, `watchdog`) від системи;
- менше конфліктів версій;
- при цьому GUI-біндінги (`python3-gi`) беруться із системи через `--system-site-packages`.

Запуск без `venv` можливий, але менш стабільний для оновлень/сумісності пакетів.
