#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List
from urllib.request import Request, urlopen

import gi
import yaml

gi.require_version("Gtk", "3.0")
gi.require_version("Notify", "0.7")
gi.require_version("AyatanaAppIndicator3", "0.1")

from gi.repository import AyatanaAppIndicator3 as AppIndicator3
from gi.repository import GLib, Gtk, Notify

from .cleanup import cleanup_events_file, normalize_cleanup_severity
from .ip_scan_backend import IPScanBackend, read_scan_history


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


HOME = Path("~/.net-monitor").expanduser()
CONFIG = HOME / "config.yaml"
HEALTH = HOME / "health.json"
SUMMARY = HOME / "summary.json"
NOTIFY_QUEUE = HOME / "notify_queue.jsonl"
OFFSET_FILE = HOME / ".notify_offset"
UI_HISTORY = HOME / "ui_history.json"
SCAN_HISTORY = HOME / "scan_history.jsonl"
PATTERNS = HOME / "patterns.yaml"

TAB_SETTINGS_INDEX = 3

LANG_LABELS = {
    "en": "English",
    "uk": "Українська",
    "ru": "Русский",
}

I18N = {
    "en": {
        "menu_open": "Open Monitor",
        "menu_settings": "Settings",
        "menu_monitoring": "Monitoring Enabled",
        "menu_popup": "Popup Notifications",
        "menu_restart": "Restart Daemon",
        "menu_quit": "Quit",
        "menu_language": "Language",
        "tab_monitor": "Monitor",
        "tab_packets": "Packets",
        "tab_tls": "TLS posture",
        "tab_settings": "Settings",
        "tab_cleanup": "Cleanup",
        "tab_advanced": "Advanced",
        "tab_geo": "Geo/ASN",
        "tab_flows": "Flows",
        "cleanup_header": "Cleanup settings",
        "cleanup_auto": "Auto cleanup old packets",
        "cleanup_interval": "Auto cleanup interval (sec)",
        "cleanup_age": "Packet age to cleanup (sec)",
        "cleanup_below": "Cleanup severities below",
        "cleanup_manual": "Manual cleanup",
        "cleanup_button": "Clean packets now",
        "save_cleanup": "Save cleanup settings",
        "scan_history": "Scan history",
        "scan_restored": "Restored scan result from history",
    },
    "uk": {
        "menu_open": "Відкрити монітор",
        "menu_settings": "Налаштування",
        "menu_monitoring": "Моніторинг увімкнено",
        "menu_popup": "Спливаючі сповіщення",
        "menu_restart": "Перезапустити демон",
        "menu_quit": "Вийти",
        "menu_language": "Мова",
        "tab_monitor": "Монітор",
        "tab_packets": "Пакети",
        "tab_tls": "TLS стан",
        "tab_settings": "Налаштування",
        "tab_cleanup": "Очищення",
        "tab_advanced": "Розширені",
        "tab_geo": "Гео/ASN",
        "tab_flows": "Потоки",
        "cleanup_header": "Налаштування очищення",
        "cleanup_auto": "Автоочищення старих пакетів",
        "cleanup_interval": "Інтервал автоочищення (сек)",
        "cleanup_age": "Вік пакетів для очищення (сек)",
        "cleanup_below": "Очищати критичність нижче",
        "cleanup_manual": "Ручне очищення",
        "cleanup_button": "Очистити пакети зараз",
        "save_cleanup": "Зберегти налаштування очищення",
        "scan_history": "Історія сканувань",
        "scan_restored": "Відновлено результат сканування з історії",
    },
    "ru": {
        "menu_open": "Открыть монитор",
        "menu_settings": "Настройки",
        "menu_monitoring": "Мониторинг включен",
        "menu_popup": "Всплывающие уведомления",
        "menu_restart": "Перезапустить демон",
        "menu_quit": "Выход",
        "menu_language": "Язык",
        "tab_monitor": "Монитор",
        "tab_packets": "Пакеты",
        "tab_tls": "TLS состояние",
        "tab_settings": "Настройки",
        "tab_cleanup": "Очистка",
        "tab_advanced": "Расширенные",
        "tab_geo": "Гео/ASN",
        "tab_flows": "Потоки",
        "cleanup_header": "Настройки очистки",
        "cleanup_auto": "Автоочистка старых пакетов",
        "cleanup_interval": "Интервал автоочистки (сек)",
        "cleanup_age": "Возраст пакетов для очистки (сек)",
        "cleanup_below": "Очищать критичность ниже",
        "cleanup_manual": "Ручная очистка",
        "cleanup_button": "Очистить пакеты сейчас",
        "save_cleanup": "Сохранить настройки очистки",
        "scan_history": "История сканирований",
        "scan_restored": "Восстановлен результат сканирования из истории",
    },
}


class NetMonitorTray:
    def __init__(self) -> None:
        HOME.mkdir(parents=True, exist_ok=True)
        Notify.init("net-monitor")
        self._updating_toggle = False
        self._updating_popup_toggle = False
        self._events_cache: List[Dict[str, Any]] = []
        self.ip_window: Gtk.Window | None = None
        self.ip_store: Gtk.ListStore | None = None
        self.window: Gtk.Window | None = None
        self.scan_backend = IPScanBackend(SCAN_HISTORY)
        self._scan_in_progress = False
        self._scan_started_ts = 0.0
        self._selected_packet_event_id = ""
        self._pin_scroll_enabled = True
        self._language = "en"

        cfg = self._read_yaml()
        tray_cfg = cfg.get("tray", {}) if isinstance(cfg.get("tray"), dict) else {}
        lang = str(tray_cfg.get("language", "en")).strip().lower()
        if lang in LANG_LABELS:
            self._language = lang

        self.indicator = AppIndicator3.Indicator.new(
            "net-monitor",
            "network-transmit-receive",
            AppIndicator3.IndicatorCategory.APPLICATION_STATUS,
        )
        self.indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self.indicator.set_menu(self._build_menu())

        self.window = self._build_window()
        self.last_notify_ts = 0
        GLib.timeout_add(500, self._refresh_status)
        GLib.timeout_add(300, self._refresh_scan_progress)
        GLib.timeout_add_seconds(1, self._poll_notifications)

    def _t(self, key: str) -> str:
        lang_map = I18N.get(self._language, I18N["en"])
        return lang_map.get(key, I18N["en"].get(key, key))

    def _on_set_language(self, _item, lang: str) -> None:
        lang = str(lang or "en").strip().lower()
        if lang not in LANG_LABELS or lang == self._language:
            return
        self._language = lang
        cfg = self._read_yaml()
        cfg.setdefault("tray", {})
        cfg["tray"]["language"] = lang
        self._write_yaml(cfg)
        self.indicator.set_menu(self._build_menu())
        if self.window is not None:
            self.window.destroy()
            self.window = self._build_window()
            self.window.show_all()

    def _build_menu(self):
        menu = Gtk.Menu()

        open_item = Gtk.MenuItem(label=self._t("menu_open"))
        open_item.connect("activate", self._on_open_monitor)
        menu.append(open_item)

        settings_item = Gtk.MenuItem(label=self._t("menu_settings"))
        settings_item.connect("activate", self._on_open_settings)
        menu.append(settings_item)

        self.monitor_toggle_item = Gtk.CheckMenuItem(label=self._t("menu_monitoring"))
        self.monitor_toggle_item.connect("toggled", self._on_toggle_monitoring)
        menu.append(self.monitor_toggle_item)

        self.popup_toggle_item = Gtk.CheckMenuItem(label=self._t("menu_popup"))
        self.popup_toggle_item.connect("toggled", self._on_toggle_popup_notifications)
        menu.append(self.popup_toggle_item)

        lang_item = Gtk.MenuItem(label=self._t("menu_language"))
        lang_menu = Gtk.Menu()
        for code in ("en", "uk", "ru"):
            item = Gtk.MenuItem(label=LANG_LABELS[code])
            item.connect("activate", self._on_set_language, code)
            lang_menu.append(item)
        lang_item.set_submenu(lang_menu)
        menu.append(lang_item)

        restart_item = Gtk.MenuItem(label=self._t("menu_restart"))
        restart_item.connect("activate", self._on_restart_daemon)
        menu.append(restart_item)

        quit_item = Gtk.MenuItem(label=self._t("menu_quit"))
        quit_item.connect("activate", self._on_quit)
        menu.append(quit_item)

        menu.show_all()
        return menu

    def _build_window(self):
        win = Gtk.Window(title="net-monitor")
        win.set_default_size(920, 620)
        win.connect("delete-event", self._on_window_delete)
        win.connect("destroy", self._on_window_destroy)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_border_width(10)

        self.stats_label = Gtk.Label(label="Status: loading...")
        self.stats_label.set_xalign(0)
        box.pack_start(self.stats_label, False, False, 0)

        self.notebook = Gtk.Notebook()

        monitor_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)

        self.overview_view = Gtk.TextView()
        self.overview_view.set_editable(False)
        self.overview_view.set_monospace(True)
        self.overview_buffer = self.overview_view.get_buffer()
        overview_scroll = Gtk.ScrolledWindow()
        overview_scroll.set_min_content_height(180)
        overview_scroll.add(self.overview_view)
        monitor_tab.pack_start(Gtk.Label(label="Detailed monitoring stats"), False, False, 0)
        monitor_tab.pack_start(overview_scroll, True, True, 0)

        self.monitor_log = Gtk.TextView()
        self.monitor_log.set_editable(False)
        self.monitor_log.set_cursor_visible(False)
        self.monitor_log_buffer = self.monitor_log.get_buffer()
        log_scroll = Gtk.ScrolledWindow()
        log_scroll.set_min_content_height(130)
        log_scroll.add(self.monitor_log)
        monitor_tab.pack_start(Gtk.Label(label="Live monitor events"), False, False, 0)
        monitor_tab.pack_start(log_scroll, True, True, 0)

        pin_scroll_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        pin_scroll_row.pack_start(Gtk.Label(label="Pin scroll (lock position during refresh)"), False, False, 0)
        self.pin_scroll_switch = Gtk.Switch()
        self.pin_scroll_switch.set_active(True)
        self.pin_scroll_switch.connect("notify::active", self._on_pin_scroll_toggled)
        pin_scroll_row.pack_start(self.pin_scroll_switch, False, False, 0)
        monitor_tab.pack_start(pin_scroll_row, False, False, 0)

        ip_btn = Gtk.Button(label="IP addresses and scan")
        ip_btn.connect("clicked", self._on_open_ip_window)
        monitor_tab.pack_start(ip_btn, False, False, 0)

        packets_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        filters = Gtk.Grid(column_spacing=8, row_spacing=8)

        self.packet_severity_combo = Gtk.ComboBoxText()
        for sev in ["all", "low", "medium", "high", "critical"]:
            self.packet_severity_combo.append_text(sev)
        self.packet_severity_combo.set_active(0)

        self.packet_protocol_combo = Gtk.ComboBoxText()
        for proto in ["all", "tcp", "udp", "icmp", "dns", "http", "tls", "ssh", "other"]:
            self.packet_protocol_combo.append_text(proto)
        self.packet_protocol_combo.set_active(0)

        self.packet_src_entry = Gtk.Entry()
        self.packet_src_entry.set_placeholder_text("src contains (e.g. 192.168.1.)")
        self.packet_dst_entry = Gtk.Entry()
        self.packet_dst_entry.set_placeholder_text("dst contains (e.g. 10.0.0.)")
        self.packet_search_entry = Gtk.Entry()
        self.packet_search_entry.set_placeholder_text("text search in event/issue/tls")

        apply_btn = Gtk.Button(label="Apply filters")
        apply_btn.connect("clicked", self._on_packets_filter_apply)
        clear_btn = Gtk.Button(label="Clear")
        clear_btn.connect("clicked", self._on_packets_filter_clear)

        filters.attach(Gtk.Label(label="Severity"), 0, 0, 1, 1)
        filters.attach(self.packet_severity_combo, 1, 0, 1, 1)
        filters.attach(Gtk.Label(label="Protocol"), 2, 0, 1, 1)
        filters.attach(self.packet_protocol_combo, 3, 0, 1, 1)
        filters.attach(Gtk.Label(label="Src"), 0, 1, 1, 1)
        filters.attach(self.packet_src_entry, 1, 1, 1, 1)
        filters.attach(Gtk.Label(label="Dst"), 2, 1, 1, 1)
        filters.attach(self.packet_dst_entry, 3, 1, 1, 1)
        filters.attach(Gtk.Label(label="Search"), 0, 2, 1, 1)
        filters.attach(self.packet_search_entry, 1, 2, 3, 1)
        filters.attach(apply_btn, 2, 3, 1, 1)
        filters.attach(clear_btn, 3, 3, 1, 1)
        packets_tab.pack_start(filters, False, False, 0)

        self.packet_store = Gtk.ListStore(str, str, str, str, str, str, str, str, str, str)
        self.packet_tree = Gtk.TreeView(model=self.packet_store)
        for idx, title in enumerate(["Time", "Src", "Dst", "Proto", "SPort", "DPort", "Severity", "Issue"]):
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(title, renderer, text=idx)
            column.set_resizable(True)
            self.packet_tree.append_column(column)
        self.packet_tree.get_selection().connect("changed", self._on_packet_selected)

        packets_scroll = Gtk.ScrolledWindow()
        packets_scroll.set_min_content_height(220)
        packets_scroll.add(self.packet_tree)
        self.packets_scroll = packets_scroll
        packets_tab.pack_start(Gtk.Label(label="Detected packets/events"), False, False, 0)
        packets_tab.pack_start(packets_scroll, True, True, 0)

        self.packet_detail_view = Gtk.TextView()
        self.packet_detail_view.set_editable(False)
        self.packet_detail_view.set_monospace(True)
        self.packet_detail_view.set_cursor_visible(False)
        self.packet_detail_buffer = self.packet_detail_view.get_buffer()
        detail_scroll = Gtk.ScrolledWindow()
        detail_scroll.set_min_content_height(180)
        detail_scroll.add(self.packet_detail_view)
        packets_tab.pack_start(Gtk.Label(label="Packet/event details"), False, False, 0)
        packets_tab.pack_start(detail_scroll, True, True, 0)

        tls_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        tls_tab.set_border_width(6)

        self.tls_score_label = Gtk.Label(label="TLS score: - | Cipher score: -")
        self.tls_score_label.set_xalign(0)
        tls_tab.pack_start(self.tls_score_label, False, False, 0)

        self.tls_hosts_view = Gtk.TextView()
        self.tls_hosts_view.set_editable(False)
        self.tls_hosts_view.set_cursor_visible(False)
        self.tls_hosts_buffer = self.tls_hosts_view.get_buffer()
        tls_hosts_scroll = Gtk.ScrolledWindow()
        tls_hosts_scroll.set_min_content_height(120)
        tls_hosts_scroll.add(self.tls_hosts_view)
        tls_tab.pack_start(Gtk.Label(label="Top problematic hosts"), False, False, 0)
        tls_tab.pack_start(tls_hosts_scroll, True, True, 0)

        self.cert_view = Gtk.TextView()
        self.cert_view.set_editable(False)
        self.cert_view.set_cursor_visible(False)
        self.cert_buffer = self.cert_view.get_buffer()
        cert_scroll = Gtk.ScrolledWindow()
        cert_scroll.set_min_content_height(140)
        cert_scroll.add(self.cert_view)
        tls_tab.pack_start(Gtk.Label(label="Certificate expiry table"), False, False, 0)
        tls_tab.pack_start(cert_scroll, True, True, 0)

        geo_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.geo_store = Gtk.ListStore(str, str, str, str, str, str)
        self.geo_tree = Gtk.TreeView(model=self.geo_store)
        for idx, title in enumerate(["Time", "Dst IP", "Country", "ASN", "Org", "Process"]):
            r = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, r, text=idx)
            col.set_resizable(True)
            self.geo_tree.append_column(col)
        geo_scroll = Gtk.ScrolledWindow()
        geo_scroll.add(self.geo_tree)
        self.geo_scroll = geo_scroll
        geo_tab.pack_start(Gtk.Label(label="Geo/IP-ASN enrichment and process mapping"), False, False, 0)
        geo_tab.pack_start(geo_scroll, True, True, 0)

        http_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.http_store = Gtk.ListStore(str, str, str, str, str, str)
        self.http_tree = Gtk.TreeView(model=self.http_store)
        for idx, title in enumerate(["Time", "Src", "Dst", "Method", "Host", "Path"]):
            r = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, r, text=idx)
            col.set_resizable(True)
            self.http_tree.append_column(col)
        http_scroll = Gtk.ScrolledWindow()
        http_scroll.add(self.http_tree)
        self.http_scroll = http_scroll
        http_tab.pack_start(Gtk.Label(label="HTTP protocol table"), False, False, 0)
        http_tab.pack_start(http_scroll, True, True, 0)

        dns_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.dns_store = Gtk.ListStore(str, str, str, str)
        self.dns_tree = Gtk.TreeView(model=self.dns_store)
        for idx, title in enumerate(["Time", "Src", "Dst", "Query"]):
            r = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, r, text=idx)
            col.set_resizable(True)
            self.dns_tree.append_column(col)
        dns_scroll = Gtk.ScrolledWindow()
        dns_scroll.add(self.dns_tree)
        self.dns_scroll = dns_scroll
        dns_tab.pack_start(Gtk.Label(label="DNS protocol table"), False, False, 0)
        dns_tab.pack_start(dns_scroll, True, True, 0)

        smtp_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.smtp_store = Gtk.ListStore(str, str, str, str, str, str)
        self.smtp_tree = Gtk.TreeView(model=self.smtp_store)
        for idx, title in enumerate(["Time", "Src", "Dst", "Command", "MAIL FROM", "RCPT TO"]):
            r = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, r, text=idx)
            col.set_resizable(True)
            self.smtp_tree.append_column(col)
        smtp_scroll = Gtk.ScrolledWindow()
        smtp_scroll.add(self.smtp_tree)
        self.smtp_scroll = smtp_scroll
        smtp_tab.pack_start(Gtk.Label(label="SMTP protocol table"), False, False, 0)
        smtp_tab.pack_start(smtp_scroll, True, True, 0)

        flows_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.flows_view = Gtk.TextView()
        self.flows_view.set_editable(False)
        self.flows_view.set_monospace(True)
        self.flows_buffer = self.flows_view.get_buffer()
        flows_scroll = Gtk.ScrolledWindow()
        flows_scroll.set_min_content_height(220)
        flows_scroll.add(self.flows_view)
        self.flows_scroll = flows_scroll
        flows_tab.pack_start(Gtk.Label(label="Realtime flow map (top edges)"), False, False, 0)
        flows_tab.pack_start(flows_scroll, True, True, 0)

        settings_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        grid = Gtk.Grid(column_spacing=8, row_spacing=8)

        advanced_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        advanced_tab.set_border_width(6)

        history = self._read_ui_history()
        iface_opts = ["all"] + self._detect_interfaces()
        target_opts = ["all"] + history.get("targets", [])
        port_opts = ["all"] + history.get("ports", [])
        proto_opts = ["all", "tcp", "udp", "icmp", "dns", "http", "tls", "ssh"]

        self.iface_combo = self._combo_with_entry(iface_opts, "all or eth0,wlan0")
        self.targets_combo = self._combo_with_entry(target_opts, "all or 192.168.1.10,10.0.0.0/24")
        self.ports_combo = self._combo_with_entry(port_opts, "all or 80,443 or 1000-2000")
        self.protocols_combo = self._combo_with_entry(proto_opts, "all or tcp,udp,http,tls")

        grid.attach(Gtk.Label(label="Interfaces"), 0, 0, 1, 1)
        grid.attach(self.iface_combo, 1, 0, 1, 1)

        grid.attach(Gtk.Label(label="Targets"), 0, 1, 1, 1)
        grid.attach(self.targets_combo, 1, 1, 1, 1)

        grid.attach(Gtk.Label(label="Ports"), 0, 2, 1, 1)
        grid.attach(self.ports_combo, 1, 2, 1, 1)

        grid.attach(Gtk.Label(label="Protocols"), 0, 3, 1, 1)
        grid.attach(self.protocols_combo, 1, 3, 1, 1)

        self.notify_severity_combo = Gtk.ComboBoxText()
        for sev in ["low", "medium", "high", "critical"]:
            self.notify_severity_combo.append_text(sev)
        self.notify_severity_combo.set_active(3)
        grid.attach(Gtk.Label(label="Notification min severity"), 0, 4, 1, 1)
        grid.attach(self.notify_severity_combo, 1, 4, 1, 1)

        self.show_packet_count_switch = Gtk.Switch()
        grid.attach(Gtk.Label(label="Show packet count near icon"), 0, 5, 1, 1)
        grid.attach(self.show_packet_count_switch, 1, 5, 1, 1)

        self.indicator_mode_combo = Gtk.ComboBoxText()
        for mode in ["risk", "total", "critical", "total+critical"]:
            self.indicator_mode_combo.append_text(mode)
        self.indicator_mode_combo.set_active(0)
        grid.attach(Gtk.Label(label="Tray indicator label mode"), 0, 6, 1, 1)
        grid.attach(self.indicator_mode_combo, 1, 6, 1, 1)

        self.persist_interval_spin = Gtk.SpinButton.new_with_range(5, 3600, 5)
        self.persist_interval_spin.set_value(60)
        grid.attach(Gtk.Label(label="Persist interval (sec)"), 0, 7, 1, 1)
        grid.attach(self.persist_interval_spin, 1, 7, 1, 1)

        self.save_events_switch = Gtk.Switch()
        grid.attach(Gtk.Label(label="Save events.jsonl"), 0, 8, 1, 1)
        grid.attach(self.save_events_switch, 1, 8, 1, 1)

        self.save_ecs_switch = Gtk.Switch()
        grid.attach(Gtk.Label(label="Save events_ecs.jsonl"), 0, 9, 1, 1)
        grid.attach(self.save_ecs_switch, 1, 9, 1, 1)

        self.save_notify_switch = Gtk.Switch()
        grid.attach(Gtk.Label(label="Save notify_queue.jsonl"), 0, 10, 1, 1)
        grid.attach(self.save_notify_switch, 1, 10, 1, 1)

        self.save_decoded_switch = Gtk.Switch()
        grid.attach(Gtk.Label(label="Save decoded_payloads.jsonl"), 0, 11, 1, 1)
        grid.attach(self.save_decoded_switch, 1, 11, 1, 1)

        self.save_min_severity_combo = Gtk.ComboBoxText()
        for sev in ["low", "medium", "high", "critical"]:
            self.save_min_severity_combo.append_text(sev)
        self.save_min_severity_combo.set_active(0)
        grid.attach(Gtk.Label(label="Min severity to save"), 0, 12, 1, 1)
        grid.attach(self.save_min_severity_combo, 1, 12, 1, 1)

        save_btn = Gtk.Button(label="Save settings")
        save_btn.connect("clicked", self._on_save)
        grid.attach(save_btn, 1, 13, 1, 1)

        settings_tab.pack_start(grid, False, False, 0)

        cleanup_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        cleanup_grid = Gtk.Grid(column_spacing=8, row_spacing=8)
        cleanup_tab.pack_start(Gtk.Label(label=self._t("cleanup_header")), False, False, 0)

        self.auto_cleanup_switch = Gtk.Switch()
        cleanup_grid.attach(Gtk.Label(label=self._t("cleanup_auto")), 0, 0, 1, 1)
        cleanup_grid.attach(self.auto_cleanup_switch, 1, 0, 1, 1)

        self.auto_cleanup_interval_spin = Gtk.SpinButton.new_with_range(5, 86400, 5)
        self.auto_cleanup_interval_spin.set_value(1800)
        cleanup_grid.attach(Gtk.Label(label=self._t("cleanup_interval")), 0, 1, 1, 1)
        cleanup_grid.attach(self.auto_cleanup_interval_spin, 1, 1, 1, 1)

        self.auto_cleanup_age_spin = Gtk.SpinButton.new_with_range(5, 604800, 5)
        self.auto_cleanup_age_spin.set_value(1800)
        cleanup_grid.attach(Gtk.Label(label=self._t("cleanup_age")), 0, 2, 1, 1)
        cleanup_grid.attach(self.auto_cleanup_age_spin, 1, 2, 1, 1)

        self.auto_cleanup_severity_combo = Gtk.ComboBoxText()
        for sev in ["low", "medium", "high", "critical", "all"]:
            self.auto_cleanup_severity_combo.append_text(sev)
        self.auto_cleanup_severity_combo.set_active(2)
        cleanup_grid.attach(Gtk.Label(label=self._t("cleanup_below")), 0, 3, 1, 1)
        cleanup_grid.attach(self.auto_cleanup_severity_combo, 1, 3, 1, 1)

        self.packet_cleanup_severity_combo = Gtk.ComboBoxText()
        for mode in ["below medium", "below high", "below critical", "all severities"]:
            self.packet_cleanup_severity_combo.append_text(mode)
        self.packet_cleanup_severity_combo.set_active(1)
        cleanup_grid.attach(Gtk.Label(label=self._t("cleanup_manual")), 0, 4, 1, 1)
        cleanup_grid.attach(self.packet_cleanup_severity_combo, 1, 4, 1, 1)

        packet_cleanup_btn = Gtk.Button(label=self._t("cleanup_button"))
        packet_cleanup_btn.connect("clicked", self._on_cleanup_packets)
        cleanup_grid.attach(packet_cleanup_btn, 1, 5, 1, 1)

        save_cleanup_btn = Gtk.Button(label=self._t("save_cleanup"))
        save_cleanup_btn.connect("clicked", self._on_save)
        cleanup_grid.attach(save_cleanup_btn, 1, 6, 1, 1)
        cleanup_tab.pack_start(cleanup_grid, False, False, 0)

        adv_grid = Gtk.Grid(column_spacing=8, row_spacing=8)

        self.rules_profile_combo = Gtk.ComboBoxText()
        for mode in ["strict", "balanced", "lenient"]:
            self.rules_profile_combo.append_text(mode)
        self.rules_profile_combo.set_active(1)
        adv_grid.attach(Gtk.Label(label="Rules profile"), 0, 0, 1, 1)
        adv_grid.attach(self.rules_profile_combo, 1, 0, 1, 1)

        self.rules_min_severity_combo = Gtk.ComboBoxText()
        for sev in ["low", "medium", "high", "critical"]:
            self.rules_min_severity_combo.append_text(sev)
        self.rules_min_severity_combo.set_active(0)
        adv_grid.attach(Gtk.Label(label="Rules min severity"), 0, 1, 1, 1)
        adv_grid.attach(self.rules_min_severity_combo, 1, 1, 1, 1)

        self.rules_dedupe_spin = Gtk.SpinButton.new_with_range(1, 600, 1)
        adv_grid.attach(Gtk.Label(label="Dedupe window (sec)"), 0, 2, 1, 1)
        adv_grid.attach(self.rules_dedupe_spin, 1, 2, 1, 1)

        self.rules_repeat_spin = Gtk.SpinButton.new_with_range(1, 100, 1)
        adv_grid.attach(Gtk.Label(label="Min repeat"), 0, 3, 1, 1)
        adv_grid.attach(self.rules_repeat_spin, 1, 3, 1, 1)

        self.runtime_stats_spin = Gtk.SpinButton.new_with_range(1, 120, 1)
        adv_grid.attach(Gtk.Label(label="Runtime stats interval (sec)"), 0, 4, 1, 1)
        adv_grid.attach(self.runtime_stats_spin, 1, 4, 1, 1)

        self.runtime_health_spin = Gtk.SpinButton.new_with_range(1, 120, 1)
        adv_grid.attach(Gtk.Label(label="Runtime health interval (sec)"), 0, 5, 1, 1)
        adv_grid.attach(self.runtime_health_spin, 1, 5, 1, 1)

        self.tls_warn_expiry_spin = Gtk.SpinButton.new_with_range(1, 365, 1)
        adv_grid.attach(Gtk.Label(label="TLS warn expiry (days)"), 0, 6, 1, 1)
        adv_grid.attach(self.tls_warn_expiry_spin, 1, 6, 1, 1)

        self.daemon_unit_entry = Gtk.Entry()
        self.daemon_unit_entry.set_placeholder_text("net-monitor.service")
        adv_grid.attach(Gtk.Label(label="Daemon service unit"), 0, 7, 1, 1)
        adv_grid.attach(self.daemon_unit_entry, 1, 7, 1, 1)

        self.tray_unit_entry = Gtk.Entry()
        self.tray_unit_entry.set_placeholder_text("net-monitor-tray.service")
        adv_grid.attach(Gtk.Label(label="Tray service unit"), 0, 8, 1, 1)
        adv_grid.attach(self.tray_unit_entry, 1, 8, 1, 1)

        self.loki_push_switch = Gtk.Switch()
        adv_grid.attach(Gtk.Label(label="Loki direct push"), 0, 9, 1, 1)
        adv_grid.attach(self.loki_push_switch, 1, 9, 1, 1)

        self.elastic_push_switch = Gtk.Switch()
        adv_grid.attach(Gtk.Label(label="Elastic direct push"), 0, 10, 1, 1)
        adv_grid.attach(self.elastic_push_switch, 1, 10, 1, 1)

        self.loki_url_entry = Gtk.Entry()
        self.loki_url_entry.set_placeholder_text("http://127.0.0.1:3100/loki/api/v1/push")
        adv_grid.attach(Gtk.Label(label="Loki URL"), 0, 11, 1, 1)
        adv_grid.attach(self.loki_url_entry, 1, 11, 1, 1)

        self.elastic_url_entry = Gtk.Entry()
        self.elastic_url_entry.set_placeholder_text("http://127.0.0.1:9200")
        adv_grid.attach(Gtk.Label(label="Elastic URL"), 0, 12, 1, 1)
        adv_grid.attach(self.elastic_url_entry, 1, 12, 1, 1)

        self.elastic_index_entry = Gtk.Entry()
        self.elastic_index_entry.set_placeholder_text("net-monitor-events")
        adv_grid.attach(Gtk.Label(label="Elastic index"), 0, 13, 1, 1)
        adv_grid.attach(self.elastic_index_entry, 1, 13, 1, 1)

        self.export_status_label = Gtk.Label(label="Export endpoints: not checked")
        self.export_status_label.set_xalign(0)
        adv_grid.attach(self.export_status_label, 0, 14, 2, 1)

        auto_export_btn = Gtk.Button(label="Auto configure exports")
        auto_export_btn.connect("clicked", self._on_auto_configure_exports)
        adv_grid.attach(auto_export_btn, 1, 15, 1, 1)

        advanced_tab.pack_start(adv_grid, False, False, 0)

        advanced_tab.pack_start(Gtk.Label(label="patterns.yaml editor"), False, False, 0)
        self.patterns_view = Gtk.TextView()
        self.patterns_view.set_monospace(True)
        self.patterns_buffer = self.patterns_view.get_buffer()
        patterns_scroll = Gtk.ScrolledWindow()
        patterns_scroll.set_min_content_height(220)
        patterns_scroll.add(self.patterns_view)
        advanced_tab.pack_start(patterns_scroll, True, True, 0)

        adv_btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        reload_patterns_btn = Gtk.Button(label="Reload patterns")
        reload_patterns_btn.connect("clicked", self._on_reload_patterns)
        adv_btn_row.pack_start(reload_patterns_btn, False, False, 0)

        save_patterns_btn = Gtk.Button(label="Save patterns")
        save_patterns_btn.connect("clicked", self._on_save_patterns)
        adv_btn_row.pack_start(save_patterns_btn, False, False, 0)

        save_adv_btn = Gtk.Button(label="Save advanced settings")
        save_adv_btn.connect("clicked", self._on_save)
        adv_btn_row.pack_start(save_adv_btn, False, False, 0)
        advanced_tab.pack_start(adv_btn_row, False, False, 0)

        self.notebook.append_page(monitor_tab, Gtk.Label(label=self._t("tab_monitor")))
        self.notebook.append_page(packets_tab, Gtk.Label(label=self._t("tab_packets")))
        self.notebook.append_page(tls_tab, Gtk.Label(label=self._t("tab_tls")))
        self.notebook.append_page(settings_tab, Gtk.Label(label=self._t("tab_settings")))
        self.notebook.append_page(cleanup_tab, Gtk.Label(label=self._t("tab_cleanup")))
        self.notebook.append_page(advanced_tab, Gtk.Label(label=self._t("tab_advanced")))
        self.notebook.append_page(geo_tab, Gtk.Label(label=self._t("tab_geo")))
        self.notebook.append_page(http_tab, Gtk.Label(label="HTTP"))
        self.notebook.append_page(dns_tab, Gtk.Label(label="DNS"))
        self.notebook.append_page(smtp_tab, Gtk.Label(label="SMTP"))
        self.notebook.append_page(flows_tab, Gtk.Label(label=self._t("tab_flows")))
        box.pack_start(self.notebook, True, True, 0)

        win.add(box)
        self._load_config_to_ui()
        return win

    def _combo_with_entry(self, options: List[str], placeholder: str) -> Gtk.ComboBoxText:
        combo = Gtk.ComboBoxText.new_with_entry()
        seen = set()
        for opt in options:
            val = str(opt).strip()
            if not val or val in seen:
                continue
            combo.append_text(val)
            seen.add(val)
        child = combo.get_child()
        if isinstance(child, Gtk.Entry):
            child.set_placeholder_text(placeholder)
        return combo

    def _combo_text(self, combo: Gtk.ComboBoxText) -> str:
        child = combo.get_child()
        if isinstance(child, Gtk.Entry):
            return child.get_text().strip()
        return (combo.get_active_text() or "").strip()

    def _set_combo_text(self, combo: Gtk.ComboBoxText, value: str) -> None:
        child = combo.get_child()
        if isinstance(child, Gtk.Entry):
            child.set_text(value)

    def _detect_interfaces(self) -> List[str]:
        sys_net = Path("/sys/class/net")
        if not sys_net.exists():
            return []
        return sorted([p.name for p in sys_net.iterdir() if p.is_dir()])

    def _read_ui_history(self) -> Dict[str, List[str]]:
        if not UI_HISTORY.exists():
            return {"ports": [], "targets": []}
        try:
            data = json.loads(UI_HISTORY.read_text(encoding="utf-8"))
        except Exception:
            return {"ports": [], "targets": []}
        if not isinstance(data, dict):
            return {"ports": [], "targets": []}
        return {
            "ports": [str(x) for x in data.get("ports", []) if str(x).strip()],
            "targets": [str(x) for x in data.get("targets", []) if str(x).strip()],
        }

    def _write_ui_history(self, payload: Dict[str, List[str]]) -> None:
        UI_HISTORY.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def _remember_history(self, key: str, value: str) -> None:
        value = value.strip()
        if not value or value.lower() == "all":
            return
        history = self._read_ui_history()
        vals = [v for v in history.get(key, []) if v != value]
        vals.insert(0, value)
        history[key] = vals[:20]
        self._write_ui_history(history)

    def _load_json(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _read_yaml(self) -> Dict[str, Any]:
        if not CONFIG.exists():
            return {}
        with CONFIG.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _write_yaml(self, payload: Dict[str, Any]) -> None:
        with CONFIG.open("w", encoding="utf-8") as f:
            yaml.safe_dump(payload, f, allow_unicode=True, sort_keys=False)

    def _load_config_to_ui(self) -> None:
        cfg = self._read_yaml()
        cap = cfg.get("capture", {})
        iface = cap.get("interfaces", ["all"])
        self._set_combo_text(self.iface_combo, ",".join(iface))

        targets = cap.get("targets", {})
        if targets.get("mode") == "all":
            self._set_combo_text(self.targets_combo, "all")
        else:
            vals = []
            vals.extend(targets.get("ips", []))
            vals.extend(targets.get("subnets", []))
            vals.extend(targets.get("ranges", []))
            self._set_combo_text(self.targets_combo, ",".join(vals))

        ports = cap.get("ports", {})
        if ports.get("mode") == "all":
            self._set_combo_text(self.ports_combo, "all")
        elif ports.get("mode") == "list":
            self._set_combo_text(self.ports_combo, ",".join(str(x) for x in ports.get("list", [])))
        else:
            self._set_combo_text(self.ports_combo, ",".join(str(x) for x in ports.get("ranges", [])))

        protos = cap.get("protocols", ["all"])
        self._set_combo_text(self.protocols_combo, ",".join(protos))

        notif_cfg = cfg.get("notifications", {})
        notif = bool(notif_cfg.get("enabled", True))
        min_sev = str(notif_cfg.get("min_severity", "critical")).lower()
        if min_sev not in SEVERITY_ORDER:
            min_sev = "critical"

        self._updating_popup_toggle = True
        self.popup_toggle_item.set_active(notif)
        self._updating_popup_toggle = False

        sev_index = ["low", "medium", "high", "critical"].index(min_sev)
        self.notify_severity_combo.set_active(sev_index)

        tray_cfg = cfg.get("tray", {})
        self.show_packet_count_switch.set_active(bool(tray_cfg.get("show_packet_count", False)))
        ind_mode = str(tray_cfg.get("indicator_label_mode", "risk"))
        ind_modes = ["risk", "total", "critical", "total+critical"]
        self.indicator_mode_combo.set_active(ind_modes.index(ind_mode) if ind_mode in ind_modes else 0)
        pin_scroll = bool(tray_cfg.get("pin_scroll", True))
        self._pin_scroll_enabled = pin_scroll
        self.pin_scroll_switch.set_active(pin_scroll)

        storage_cfg = cfg.get("storage", {})
        self.persist_interval_spin.set_value(float(storage_cfg.get("flush_interval_sec", 60) or 60))
        self.save_events_switch.set_active(bool(storage_cfg.get("save_events_jsonl", True)))
        self.save_ecs_switch.set_active(bool(storage_cfg.get("save_ecs_jsonl", True)))
        self.save_notify_switch.set_active(bool(storage_cfg.get("save_notify_jsonl", True)))
        self.save_decoded_switch.set_active(bool(storage_cfg.get("save_decoded_payloads", True)))
        save_min = str(storage_cfg.get("min_severity_to_save", "low")).lower()
        sev_modes = ["low", "medium", "high", "critical"]
        self.save_min_severity_combo.set_active(sev_modes.index(save_min) if save_min in sev_modes else 0)
        cleanup_cfg = storage_cfg.get("cleanup", {}) if isinstance(storage_cfg.get("cleanup"), dict) else {}
        self.auto_cleanup_switch.set_active(bool(cleanup_cfg.get("enabled", False)))
        self.auto_cleanup_interval_spin.set_value(float(cleanup_cfg.get("interval_sec", 1800) or 1800))
        self.auto_cleanup_age_spin.set_value(float(cleanup_cfg.get("older_than_sec", 1800) or 1800))
        cleanup_below = normalize_cleanup_severity(str(cleanup_cfg.get("severity_below", "high")))
        cleanup_modes = ["low", "medium", "high", "critical", "all"]
        self.auto_cleanup_severity_combo.set_active(cleanup_modes.index(cleanup_below) if cleanup_below in cleanup_modes else 2)

        rules_cfg = cfg.get("rules", {})
        profile = str(rules_cfg.get("profile", "balanced")).lower()
        profiles = ["strict", "balanced", "lenient"]
        self.rules_profile_combo.set_active(profiles.index(profile) if profile in profiles else 1)
        rules_min = str(rules_cfg.get("min_severity", "low")).lower()
        self.rules_min_severity_combo.set_active(sev_modes.index(rules_min) if rules_min in sev_modes else 0)
        self.rules_dedupe_spin.set_value(float(rules_cfg.get("dedupe_window_sec", 20) or 20))
        self.rules_repeat_spin.set_value(float(rules_cfg.get("min_repeat", 1) or 1))

        runtime_cfg = cfg.get("runtime", {})
        self.runtime_stats_spin.set_value(float(runtime_cfg.get("stats_interval_sec", 5) or 5))
        self.runtime_health_spin.set_value(float(runtime_cfg.get("health_interval_sec", 5) or 5))

        tls_cfg = cfg.get("tls_audit", {})
        self.tls_warn_expiry_spin.set_value(float(tls_cfg.get("warn_expiry_days", 14) or 14))

        svc_cfg = cfg.get("services", {})
        self.daemon_unit_entry.set_text(str(svc_cfg.get("daemon_unit", "net-monitor.service") or "net-monitor.service"))
        self.tray_unit_entry.set_text(str(svc_cfg.get("tray_unit", "net-monitor-tray.service") or "net-monitor-tray.service"))

        exports_cfg = cfg.get("exports", {})
        loki_cfg = exports_cfg.get("loki", {}) if isinstance(exports_cfg.get("loki"), dict) else {}
        elastic_cfg = exports_cfg.get("elastic", {}) if isinstance(exports_cfg.get("elastic"), dict) else {}
        self.loki_push_switch.set_active(bool(loki_cfg.get("enabled", False) and loki_cfg.get("direct_push", False)))
        self.elastic_push_switch.set_active(bool(elastic_cfg.get("enabled", False) and elastic_cfg.get("direct_push", False)))
        self.loki_url_entry.set_text(str(loki_cfg.get("url", "http://127.0.0.1:3100/loki/api/v1/push") or "http://127.0.0.1:3100/loki/api/v1/push"))
        self.elastic_url_entry.set_text(str(elastic_cfg.get("url", "http://127.0.0.1:9200") or "http://127.0.0.1:9200"))
        self.elastic_index_entry.set_text(str(elastic_cfg.get("index", "net-monitor-events") or "net-monitor-events"))
        self._refresh_export_status(cfg)

        self._load_patterns_to_ui()

    def _on_save(self, _btn) -> None:
        cfg = self._read_yaml()
        cfg.setdefault("capture", {})
        cfg.setdefault("notifications", {})
        cfg.setdefault("tray", {})
        cfg.setdefault("rules", {})
        cfg.setdefault("runtime", {})
        cfg.setdefault("tls_audit", {})
        cfg.setdefault("services", {})
        cfg.setdefault("exports", {})

        iface_raw = self._combo_text(self.iface_combo)
        interfaces = [x.strip() for x in iface_raw.split(",") if x.strip()] or ["all"]
        cfg["capture"]["interfaces"] = interfaces

        targets_raw = self._combo_text(self.targets_combo)
        t = {"mode": "all", "ips": [], "subnets": [], "ranges": []}
        if targets_raw and targets_raw.lower() != "all":
            parts = [x.strip() for x in targets_raw.split(",") if x.strip()]
            mode = "mixed"
            for p in parts:
                if "-" in p and "/" not in p:
                    t["ranges"].append(p)
                elif "/" in p:
                    t["subnets"].append(p)
                else:
                    t["ips"].append(p)
            t["mode"] = mode
        cfg["capture"]["targets"] = t

        ports_raw = self._combo_text(self.ports_combo)
        p_cfg = {"mode": "all", "list": [], "ranges": []}
        if ports_raw and ports_raw.lower() != "all":
            vals = [x.strip() for x in ports_raw.split(",") if x.strip()]
            has_range = any("-" in x for x in vals)
            if has_range:
                p_cfg["mode"] = "range"
                p_cfg["ranges"] = vals
            else:
                p_cfg["mode"] = "list"
                p_cfg["list"] = [int(x) for x in vals if x.isdigit()]
        cfg["capture"]["ports"] = p_cfg

        protos_raw = self._combo_text(self.protocols_combo)
        cfg["capture"]["protocols"] = [x.strip().lower() for x in protos_raw.split(",") if x.strip()] or ["all"]

        cfg["notifications"]["enabled"] = bool(self.popup_toggle_item.get_active())
        cfg["notifications"]["min_severity"] = (self.notify_severity_combo.get_active_text() or "critical").strip().lower()
        cfg["tray"]["show_packet_count"] = bool(self.show_packet_count_switch.get_active())
        cfg["tray"]["indicator_label_mode"] = (self.indicator_mode_combo.get_active_text() or "risk").strip().lower()
        cfg["tray"]["pin_scroll"] = bool(self.pin_scroll_switch.get_active())
        cfg["tray"]["language"] = self._language
        cfg.setdefault("storage", {})
        cfg["storage"]["flush_interval_sec"] = int(self.persist_interval_spin.get_value())
        cfg["storage"]["save_events_jsonl"] = bool(self.save_events_switch.get_active())
        cfg["storage"]["save_ecs_jsonl"] = bool(self.save_ecs_switch.get_active())
        cfg["storage"]["save_notify_jsonl"] = bool(self.save_notify_switch.get_active())
        cfg["storage"]["save_decoded_payloads"] = bool(self.save_decoded_switch.get_active())
        cfg["storage"]["min_severity_to_save"] = (self.save_min_severity_combo.get_active_text() or "low").strip().lower()
        cfg["storage"].setdefault("cleanup", {})
        cfg["storage"]["cleanup"]["enabled"] = bool(self.auto_cleanup_switch.get_active())
        cfg["storage"]["cleanup"]["interval_sec"] = int(self.auto_cleanup_interval_spin.get_value())
        cfg["storage"]["cleanup"]["older_than_sec"] = int(self.auto_cleanup_age_spin.get_value())
        cfg["storage"]["cleanup"]["severity_below"] = normalize_cleanup_severity(
            (self.auto_cleanup_severity_combo.get_active_text() or "high").strip().lower()
        )

        cfg["rules"]["profile"] = (self.rules_profile_combo.get_active_text() or "balanced").strip().lower()
        cfg["rules"]["min_severity"] = (self.rules_min_severity_combo.get_active_text() or "low").strip().lower()
        cfg["rules"]["dedupe_window_sec"] = int(self.rules_dedupe_spin.get_value())
        cfg["rules"]["min_repeat"] = int(self.rules_repeat_spin.get_value())

        cfg["runtime"]["stats_interval_sec"] = int(self.runtime_stats_spin.get_value())
        cfg["runtime"]["health_interval_sec"] = int(self.runtime_health_spin.get_value())

        cfg["tls_audit"]["warn_expiry_days"] = int(self.tls_warn_expiry_spin.get_value())

        cfg["services"]["daemon_unit"] = self.daemon_unit_entry.get_text().strip() or "net-monitor.service"
        cfg["services"]["tray_unit"] = self.tray_unit_entry.get_text().strip() or "net-monitor-tray.service"

        cfg["exports"].setdefault("loki", {})
        cfg["exports"].setdefault("elastic", {})
        cfg["exports"]["loki"]["enabled"] = bool(self.loki_push_switch.get_active())
        cfg["exports"]["loki"]["direct_push"] = bool(self.loki_push_switch.get_active())
        cfg["exports"]["loki"]["detect_on_start"] = True
        cfg["exports"]["loki"]["timeout_sec"] = int(cfg["exports"]["loki"].get("timeout_sec", 3) or 3)
        cfg["exports"]["loki"]["url"] = self.loki_url_entry.get_text().strip() or "http://127.0.0.1:3100/loki/api/v1/push"

        cfg["exports"]["elastic"]["enabled"] = bool(self.elastic_push_switch.get_active())
        cfg["exports"]["elastic"]["direct_push"] = bool(self.elastic_push_switch.get_active())
        cfg["exports"]["elastic"]["detect_on_start"] = True
        cfg["exports"]["elastic"]["timeout_sec"] = int(cfg["exports"]["elastic"].get("timeout_sec", 3) or 3)
        cfg["exports"]["elastic"]["url"] = self.elastic_url_entry.get_text().strip() or "http://127.0.0.1:9200"
        cfg["exports"]["elastic"]["index"] = self.elastic_index_entry.get_text().strip() or "net-monitor-events"
        cfg["exports"]["elastic"]["bulk_url"] = cfg["exports"]["elastic"]["url"].rstrip("/") + "/_bulk"

        self._write_yaml(cfg)
        self._refresh_export_status(cfg)
        self._remember_history("targets", targets_raw)
        self._remember_history("ports", ports_raw)
        self._append_text("Settings saved to ~/.net-monitor/config.yaml\n")

    def _probe_url(self, url: str, timeout_sec: int = 2) -> bool:
        url = str(url or "").strip()
        if not url:
            return False
        try:
            req = Request(url, method="GET")
            with urlopen(req, timeout=timeout_sec) as resp:
                code = int(resp.getcode() or 0)
                return 200 <= code < 500
        except Exception:
            return False

    def _refresh_export_status(self, cfg: Dict[str, Any]) -> None:
        exports_cfg = cfg.get("exports", {}) if isinstance(cfg.get("exports"), dict) else {}
        loki_cfg = exports_cfg.get("loki", {}) if isinstance(exports_cfg.get("loki"), dict) else {}
        elastic_cfg = exports_cfg.get("elastic", {}) if isinstance(exports_cfg.get("elastic"), dict) else {}
        loki_state = "on" if bool(loki_cfg.get("enabled", False) and loki_cfg.get("direct_push", False)) else "off"
        elastic_state = "on" if bool(elastic_cfg.get("enabled", False) and elastic_cfg.get("direct_push", False)) else "off"
        if hasattr(self, "export_status_label"):
            self.export_status_label.set_text(f"Export direct push: Loki={loki_state}, Elastic={elastic_state}")

    def _on_auto_configure_exports(self, _btn) -> None:
        cfg = self._read_yaml()
        cfg.setdefault("exports", {})
        cfg["exports"].setdefault("loki", {})
        cfg["exports"].setdefault("elastic", {})

        loki_url = self.loki_url_entry.get_text().strip() or "http://127.0.0.1:3100/loki/api/v1/push"
        loki_ready = loki_url
        if "/loki/api/v1/push" in loki_url:
            loki_ready = loki_url.split("/loki/api/v1/push", 1)[0].rstrip("/") + "/ready"
        loki_ok = self._probe_url(loki_ready, timeout_sec=2)

        elastic_url = self.elastic_url_entry.get_text().strip() or "http://127.0.0.1:9200"
        elastic_ok = self._probe_url(elastic_url, timeout_sec=2)

        cfg["exports"]["loki"]["enabled"] = bool(loki_ok)
        cfg["exports"]["loki"]["direct_push"] = bool(loki_ok)
        cfg["exports"]["loki"]["detect_on_start"] = True
        cfg["exports"]["loki"]["timeout_sec"] = int(cfg["exports"]["loki"].get("timeout_sec", 3) or 3)
        cfg["exports"]["loki"]["url"] = loki_url

        cfg["exports"]["elastic"]["enabled"] = bool(elastic_ok)
        cfg["exports"]["elastic"]["direct_push"] = bool(elastic_ok)
        cfg["exports"]["elastic"]["detect_on_start"] = True
        cfg["exports"]["elastic"]["timeout_sec"] = int(cfg["exports"]["elastic"].get("timeout_sec", 3) or 3)
        cfg["exports"]["elastic"]["url"] = elastic_url
        cfg["exports"]["elastic"]["index"] = self.elastic_index_entry.get_text().strip() or "net-monitor-events"
        cfg["exports"]["elastic"]["bulk_url"] = elastic_url.rstrip("/") + "/_bulk"

        self.loki_push_switch.set_active(bool(loki_ok))
        self.elastic_push_switch.set_active(bool(elastic_ok))
        self._write_yaml(cfg)
        self._refresh_export_status(cfg)
        self._append_text(f"Auto-config exports: Loki={'ok' if loki_ok else 'down'}, Elastic={'ok' if elastic_ok else 'down'}\n")

    def _load_patterns_to_ui(self) -> None:
        if not hasattr(self, "patterns_buffer"):
            return
        if not PATTERNS.exists():
            self.patterns_buffer.set_text("# patterns.yaml is missing\n")
            return
        try:
            txt = PATTERNS.read_text(encoding="utf-8")
        except Exception as exc:
            self.patterns_buffer.set_text(f"# failed to read patterns.yaml: {exc}\n")
            return
        self.patterns_buffer.set_text(txt)

    def _on_reload_patterns(self, _btn) -> None:
        self._load_patterns_to_ui()
        self._append_text("patterns.yaml reloaded\n")

    def _on_save_patterns(self, _btn) -> None:
        start = self.patterns_buffer.get_start_iter()
        end = self.patterns_buffer.get_end_iter()
        txt = self.patterns_buffer.get_text(start, end, True)
        try:
            parsed = yaml.safe_load(txt) if txt.strip() else {}
            if parsed is not None and not isinstance(parsed, (dict, list)):
                raise ValueError("patterns.yaml must be mapping or list")
            PATTERNS.write_text(txt, encoding="utf-8")
            self._append_text("patterns.yaml saved\n")
        except Exception as exc:
            self._append_text(f"Failed to save patterns.yaml: {exc}\n")

    def _append_text(self, text: str) -> None:
        end = self.monitor_log_buffer.get_end_iter()
        self.monitor_log_buffer.insert(end, text)

    def _on_pin_scroll_toggled(self, _switch, _param) -> None:
        self._pin_scroll_enabled = bool(self.pin_scroll_switch.get_active())

    def _is_pin_scroll_enabled(self) -> bool:
        return bool(getattr(self, "_pin_scroll_enabled", True))

    def _capture_vscroll(self, scrolled: Gtk.ScrolledWindow | None) -> float | None:
        if scrolled is None:
            return None
        adj = scrolled.get_vadjustment()
        if adj is None:
            return None
        return float(adj.get_value())

    def _restore_vscroll(self, scrolled: Gtk.ScrolledWindow | None, value: float | None) -> None:
        if scrolled is None:
            return
        adj = scrolled.get_vadjustment()
        if adj is None:
            return
        upper = float(adj.get_upper())
        page = float(adj.get_page_size())
        max_val = max(0.0, upper - page)
        if value is None:
            return
        adj.set_value(max(0.0, min(max_val, float(value))))

    def _capture_tree_selection(self, tree: Gtk.TreeView, value_columns: List[int]) -> List[str]:
        model, tree_iter = tree.get_selection().get_selected()
        if tree_iter is None:
            return []
        vals: List[str] = []
        for idx in value_columns:
            vals.append(str(model.get_value(tree_iter, idx) or ""))
        return vals

    def _restore_tree_selection(self, tree: Gtk.TreeView, value_columns: List[int], selection_values: List[str]) -> None:
        if not selection_values:
            return
        model = tree.get_model()
        if model is None:
            return
        it = model.get_iter_first()
        while it is not None:
            row_vals = [str(model.get_value(it, idx) or "") for idx in value_columns]
            if row_vals == selection_values:
                tree.get_selection().select_iter(it)
                break
            it = model.iter_next(it)

    def _set_tab(self, index: int) -> None:
        if self.window is None or self.window.get_child() is None:
            self.window = self._build_window()
        self.notebook.set_current_page(index)
        self.window.show_all()
        self.window.present()

    def _on_window_delete(self, _win, _event):
        self.window.hide()
        return True

    def _on_window_destroy(self, *_args) -> None:
        self.window = None

    def _on_open_monitor(self, _item) -> None:
        self._set_tab(0)

    def _on_open_settings(self, _item) -> None:
        self._set_tab(TAB_SETTINGS_INDEX)

    def _daemon_unit_name(self) -> str:
        cfg = self._read_yaml()
        services = cfg.get("services", {})
        return str(services.get("daemon_unit", "net-monitor.service") or "net-monitor.service")

    def _on_toggle_popup_notifications(self, item) -> None:
        if self._updating_popup_toggle:
            return
        cfg = self._read_yaml()
        cfg.setdefault("notifications", {})
        cfg["notifications"]["enabled"] = bool(item.get_active())
        if not cfg["notifications"].get("min_severity"):
            cfg["notifications"]["min_severity"] = "critical"
        self._write_yaml(cfg)
        state = "enabled" if item.get_active() else "disabled"
        self._append_text(f"Popup notifications {state}\n")

    def _daemon_is_active(self) -> bool:
        result = subprocess.run(["systemctl", "is-active", self._daemon_unit_name()], capture_output=True, text=True, check=False)
        return result.returncode == 0 and result.stdout.strip() == "active"

    def _daemon_control(self, action: str) -> bool:
        unit = self._daemon_unit_name()
        for cmd in (
            ["systemctl", action, unit],
            ["pkexec", "systemctl", action, unit],
            ["sudo", "-n", "systemctl", action, unit],
        ):
            try:
                res = subprocess.run(cmd, check=False)
            except FileNotFoundError:
                continue
            if res.returncode == 0:
                return True
        return False

    def _on_toggle_monitoring(self, item) -> None:
        if self._updating_toggle:
            return
        desired = bool(item.get_active())
        ok = self._daemon_control("start" if desired else "stop")
        if not ok:
            self._append_text("Failed to change monitoring state (need privileges)\n")
            self._notify("net-monitor", "Failed to change monitoring state. Use sudo/systemd manually.")
            self._updating_toggle = True
            item.set_active(not desired)
            self._updating_toggle = False
        else:
            self._append_text(f"Monitoring {'enabled' if desired else 'disabled'}\n")

    def _on_restart_daemon(self, _item) -> None:
        if self._daemon_control("restart"):
            self._append_text("Requested daemon restart\n")
        else:
            self._append_text("Failed to restart daemon (need privileges)\n")

    def _on_quit(self, _item) -> None:
        Gtk.main_quit()

    def _best_severity(self, summary: Dict[str, Any], events: List[Dict[str, Any]]) -> str:
        issues_by = summary.get("issues_by_severity", {})
        if isinstance(issues_by, dict):
            for sev in ("critical", "high", "medium", "low"):
                if int(issues_by.get(sev, 0) or 0) > 0:
                    return sev

        top = "low"
        for ev in events[-100:]:
            sev = str(ev.get("severity", "low")).lower()
            if SEVERITY_ORDER.get(sev, 1) > SEVERITY_ORDER.get(top, 1):
                top = sev
        return top

    def _icon_name_for_state(self, daemon_active: bool, severity: str) -> str:
        if not daemon_active:
            return "process-stop"
        mapping = {
            "critical": "network-error",
            "high": "dialog-warning",
            "medium": "dialog-information",
            "low": "emblem-default",
        }
        return mapping.get(severity, "network-transmit-receive")

    def _update_indicator(self, daemon_active: bool, severity: str, risk: Any, packets_total: int, critical_count: int) -> None:
        icon_name = self._icon_name_for_state(daemon_active, severity)
        self.indicator.set_icon_full(icon_name, f"state={severity}")

        cfg = self._read_yaml()
        tray_cfg = cfg.get("tray", {})
        show_packets = bool(cfg.get("tray", {}).get("show_packet_count", False))
        label_mode = str(tray_cfg.get("indicator_label_mode", "risk")).lower()
        if not daemon_active:
            self.indicator.set_label("off", "")
            return
        label_map = {
            "risk": f"R:{risk}",
            "total": f"T:{packets_total}",
            "critical": f"C:{critical_count}",
            "total+critical": f"T:{packets_total} C:{critical_count}",
        }
        base_label = label_map.get(label_mode, f"R:{risk}")
        if show_packets:
            self.indicator.set_label(f"P:{packets_total} {base_label}", "")
        else:
            self.indicator.set_label(base_label, "")

    def _refresh_status(self):
        health = self._load_json(HEALTH)
        summary = self._load_json(SUMMARY)
        events = self._read_last_events(300)
        self._events_cache = events

        if self.ip_window is not None and self.ip_window.get_visible():
            self._refresh_ip_store(events)

        daemon_active = self._daemon_is_active()
        self._updating_toggle = True
        self.monitor_toggle_item.set_active(daemon_active)
        self._updating_toggle = False

        packets = health.get("packets", {})
        risk = health.get("risk_score", summary.get("risk_score", 0))
        txt = (
            f"Packets total={packets.get('total',0)} target={packets.get('target',0)} "
            f"alerts={packets.get('alerts',0)} dropped={packets.get('dropped',0)} risk={risk} daemon={'on' if daemon_active else 'off'}"
        )
        self.stats_label.set_text(txt)
        best_sev = self._best_severity(summary, events)
        crit_cnt = int((summary.get("issues_by_severity", {}) or {}).get("critical", 0) or 0)
        self._update_indicator(daemon_active, best_sev, risk, int(packets.get("total", 0) or 0), crit_cnt)

        detailed = {
            "packets": packets,
            "issues_by_severity": health.get("issues_by_severity", summary.get("issues_by_severity", {})),
            "protocols": health.get("protocols", summary.get("protocol_inventory", {})),
            "scores": {
                "risk_score": summary.get("risk_score", risk),
                "tls_score": summary.get("tls_score", "-"),
                "cipher_score": summary.get("cipher_score", "-"),
            },
        }
        if not self.overview_view.is_focus():
            self.overview_buffer.set_text(json.dumps(detailed, ensure_ascii=False, indent=2))

        tls_score = summary.get("tls_score", "-")
        cipher_score = summary.get("cipher_score", "-")
        self.tls_score_label.set_text(f"TLS score: {tls_score} | Cipher score: {cipher_score}")

        issues = summary.get("issues", []) if isinstance(summary.get("issues"), list) else []
        host_counter: Dict[str, int] = {}
        cert_rows = []
        for issue in issues:
            src = str(issue.get("src_ip", "?"))
            dst = str(issue.get("dst_ip", "?"))
            key = f"{src} -> {dst}"
            host_counter[key] = host_counter.get(key, 0) + int(issue.get("seen_count", 1))

        top_hosts = sorted(host_counter.items(), key=lambda x: x[1], reverse=True)[:8]
        host_text = "\n".join([f"{h}: {c}" for h, c in top_hosts]) or "No problematic hosts yet"
        if not self.tls_hosts_view.is_focus():
            self.tls_hosts_buffer.set_text(host_text)

        if events:
            for ev in events:
                tls = ev.get("tls", {})
                subj = tls.get("leaf_subject")
                exp = tls.get("leaf_days_to_expiry")
                sni = tls.get("sni")
                if subj is not None and exp is not None:
                    cert_rows.append(f"sni={sni or '-'} | days={exp} | subject={subj[:80]}")
        cert_text = "\n".join(cert_rows[:20]) or "No certificate data yet"
        if not self.cert_view.is_focus():
            self.cert_buffer.set_text(cert_text)
        self._refresh_packets_table(events)
        self._refresh_geo_table(events)
        self._refresh_protocol_tables(summary)
        self._refresh_flows_view(summary)
        return True

    def _refresh_geo_table(self, events: List[Dict[str, Any]]) -> None:
        if not hasattr(self, "geo_store"):
            return
        selected_row = self._capture_tree_selection(self.geo_tree, [0, 1, 2, 3, 4, 5])
        prev_scroll = self._capture_vscroll(getattr(self, "geo_scroll", None))
        self.geo_store.clear()
        for ev in reversed(events[-250:]):
            geo = ev.get("geo", {}) if isinstance(ev.get("geo"), dict) else {}
            dst_geo = geo.get("dst", {}) if isinstance(geo.get("dst"), dict) else {}
            proc = ev.get("process", {}) if isinstance(ev.get("process"), dict) else {}
            ts = int(ev.get("timestamp", 0))
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"
            proc_label = "-"
            if proc:
                proc_label = f"{proc.get('name','?')}:{proc.get('pid','?')}"
            self.geo_store.append([
                ts_str,
                str(ev.get("dst_ip", "-")),
                str(dst_geo.get("country", "-")),
                str(dst_geo.get("asn", "-")),
                str(dst_geo.get("org", "-")),
                proc_label,
            ])
        self._restore_tree_selection(self.geo_tree, [0, 1, 2, 3, 4, 5], selected_row)
        self._restore_vscroll(getattr(self, "geo_scroll", None), prev_scroll)

    def _refresh_protocol_tables(self, summary: Dict[str, Any]) -> None:
        tables = summary.get("protocol_tables", {}) if isinstance(summary.get("protocol_tables"), dict) else {}

        http_selected = self._capture_tree_selection(self.http_tree, [0, 1, 2, 3, 4, 5])
        http_scroll = self._capture_vscroll(getattr(self, "http_scroll", None))
        self.http_store.clear()
        for row in reversed((tables.get("http", []) if isinstance(tables.get("http"), list) else [])[-250:]):
            ts = int(row.get("timestamp", 0) or 0)
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"
            self.http_store.append([
                ts_str,
                str(row.get("src_ip", "-")),
                str(row.get("dst_ip", "-")),
                str(row.get("method", "-")),
                str(row.get("host", "-")),
                str(row.get("path", "-")),
            ])
        self._restore_tree_selection(self.http_tree, [0, 1, 2, 3, 4, 5], http_selected)
        self._restore_vscroll(getattr(self, "http_scroll", None), http_scroll)

        dns_selected = self._capture_tree_selection(self.dns_tree, [0, 1, 2, 3])
        dns_scroll = self._capture_vscroll(getattr(self, "dns_scroll", None))
        self.dns_store.clear()
        for row in reversed((tables.get("dns", []) if isinstance(tables.get("dns"), list) else [])[-250:]):
            ts = int(row.get("timestamp", 0) or 0)
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"
            self.dns_store.append([
                ts_str,
                str(row.get("src_ip", "-")),
                str(row.get("dst_ip", "-")),
                str(row.get("query", "-")),
            ])
        self._restore_tree_selection(self.dns_tree, [0, 1, 2, 3], dns_selected)
        self._restore_vscroll(getattr(self, "dns_scroll", None), dns_scroll)

        smtp_selected = self._capture_tree_selection(self.smtp_tree, [0, 1, 2, 3, 4, 5])
        smtp_scroll = self._capture_vscroll(getattr(self, "smtp_scroll", None))
        self.smtp_store.clear()
        for row in reversed((tables.get("smtp", []) if isinstance(tables.get("smtp"), list) else [])[-250:]):
            ts = int(row.get("timestamp", 0) or 0)
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"
            self.smtp_store.append([
                ts_str,
                str(row.get("src_ip", "-")),
                str(row.get("dst_ip", "-")),
                str(row.get("command", "-")),
                str(row.get("mail_from", "-")),
                str(row.get("rcpt_to", "-")),
            ])
        self._restore_tree_selection(self.smtp_tree, [0, 1, 2, 3, 4, 5], smtp_selected)
        self._restore_vscroll(getattr(self, "smtp_scroll", None), smtp_scroll)

    def _refresh_flows_view(self, summary: Dict[str, Any]) -> None:
        if not hasattr(self, "flows_buffer"):
            return
        prev_scroll = self._capture_vscroll(getattr(self, "flows_scroll", None))
        flow_graph = summary.get("flow_graph", {}) if isinstance(summary.get("flow_graph"), dict) else {}
        edges = flow_graph.get("top_edges", []) if isinstance(flow_graph.get("top_edges"), list) else []
        behavior = summary.get("behavior", {}) if isinstance(summary.get("behavior"), dict) else {}
        anomalies = behavior.get("anomalies", {}) if isinstance(behavior.get("anomalies"), dict) else {}

        lines = ["Top flows:"]
        for item in edges[:80]:
            if not isinstance(item, dict):
                continue
            lines.append(f"- {item.get('edge','-')}  count={item.get('count',0)}")

        lines.append("\nBehavior anomalies:")
        if anomalies:
            for key, value in anomalies.items():
                lines.append(f"- {key}: {value}")
        else:
            lines.append("- none")
        if not self.flows_view.is_focus():
            self.flows_buffer.set_text("\n".join(lines))
        self._restore_vscroll(getattr(self, "flows_scroll", None), prev_scroll)

    def _refresh_packets_table(self, events: List[Dict[str, Any]]) -> None:
        selected_id = self._selected_packet_event_id
        sel_model, sel_iter = self.packet_tree.get_selection().get_selected()
        if sel_iter is not None:
            selected_id = str(sel_model.get_value(sel_iter, 9) or selected_id)

        prev_scroll = self._capture_vscroll(getattr(self, "packets_scroll", None))
        self.packet_store.clear()
        for ev in reversed(self._filter_packet_events(events)[-200:]):
            issues = ev.get("issues", [])
            top_issue = issues[0].get("title", "-") if issues else "-"
            ts = int(ev.get("timestamp", 0))
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"
            ev_id = str(ev.get("event_id", ""))
            row = [
                ts_str,
                str(ev.get("src_ip", "-")),
                str(ev.get("dst_ip", "-")),
                str(ev.get("protocol", "-")),
                str(ev.get("src_port", "-")),
                str(ev.get("dst_port", "-")),
                str(ev.get("severity", "-")),
                str(top_issue),
                json.dumps(ev, ensure_ascii=False, indent=2),
                ev_id,
            ]
            self.packet_store.append(row)

        if selected_id:
            it = self.packet_store.get_iter_first()
            while it is not None:
                if str(self.packet_store.get_value(it, 9)) == selected_id:
                    self.packet_tree.get_selection().select_iter(it)
                    break
                it = self.packet_store.iter_next(it)
        self._restore_vscroll(getattr(self, "packets_scroll", None), prev_scroll)

    def _filter_packet_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        sev = (self.packet_severity_combo.get_active_text() or "all").strip().lower()
        proto = (self.packet_protocol_combo.get_active_text() or "all").strip().lower()
        src_q = self.packet_src_entry.get_text().strip().lower()
        dst_q = self.packet_dst_entry.get_text().strip().lower()
        text_q = self.packet_search_entry.get_text().strip().lower()

        filtered: List[Dict[str, Any]] = []
        for ev in events:
            ev_sev = str(ev.get("severity", "")).lower()
            ev_proto = str(ev.get("protocol", "")).lower()
            ev_src = str(ev.get("src_ip", "")).lower()
            ev_dst = str(ev.get("dst_ip", "")).lower()

            if sev != "all" and ev_sev != sev:
                continue
            if proto != "all" and ev_proto != proto:
                continue
            if src_q and src_q not in ev_src:
                continue
            if dst_q and dst_q not in ev_dst:
                continue
            if text_q:
                blob = json.dumps(ev, ensure_ascii=False).lower()
                if text_q not in blob:
                    continue
            filtered.append(ev)
        return filtered

    def _on_packets_filter_apply(self, _btn) -> None:
        self._refresh_packets_table(self._events_cache)

    def _on_packets_filter_clear(self, _btn) -> None:
        self.packet_severity_combo.set_active(0)
        self.packet_protocol_combo.set_active(0)
        self.packet_src_entry.set_text("")
        self.packet_dst_entry.set_text("")
        self.packet_search_entry.set_text("")
        self._refresh_packets_table(self._events_cache)

    def _on_cleanup_packets(self, _btn) -> None:
        mode = (self.packet_cleanup_severity_combo.get_active_text() or "below high").strip().lower()
        severity_map = {
            "below medium": "medium",
            "below high": "high",
            "below critical": "critical",
            "all severities": "all",
        }
        cleanup_below = severity_map.get(mode, "high")

        removed, remaining = cleanup_events_file(
            HOME / "events.jsonl",
            int(time.time()),
            cleanup_below=cleanup_below,
            older_than_sec=1,
            force=True,
        )
        self._events_cache = self._read_last_events(300)
        self._refresh_packets_table(self._events_cache)
        self._append_text(
            f"Manual cleanup: removed={removed}, remaining={remaining}, mode={cleanup_below}\n"
        )

    def _on_packet_selected(self, selection) -> None:
        model, tree_iter = selection.get_selected()
        if tree_iter is None:
            return
        self._selected_packet_event_id = str(model.get_value(tree_iter, 9) or "")
        details = model.get_value(tree_iter, 8)
        self.packet_detail_buffer.set_text(details)

    def _read_last_events(self, max_lines: int) -> list:
        events_path = HOME / "events.jsonl"
        if not events_path.exists():
            return []
        try:
            lines = events_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            out = []
            for line in lines[-max_lines:]:
                if not line.strip():
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return out
        except Exception:
            return []

    def _poll_notifications(self):
        if not NOTIFY_QUEUE.exists():
            return True

        cfg = self._read_yaml()
        notif_cfg = cfg.get("notifications", {})
        popup_enabled = bool(notif_cfg.get("enabled", True))
        min_sev = str(notif_cfg.get("min_severity", "critical")).lower()
        if min_sev not in SEVERITY_ORDER:
            min_sev = "critical"

        self._updating_popup_toggle = True
        self.popup_toggle_item.set_active(popup_enabled)
        self._updating_popup_toggle = False

        offset = 0
        if OFFSET_FILE.exists():
            try:
                offset = int(OFFSET_FILE.read_text(encoding="utf-8").strip() or "0")
            except Exception:
                offset = 0

        with NOTIFY_QUEUE.open("r", encoding="utf-8") as f:
            f.seek(offset)
            chunk = f.read()
            new_offset = f.tell()

        if chunk.strip():
            for line in chunk.splitlines():
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = int(item.get("timestamp", 0))
                if ts <= self.last_notify_ts:
                    continue
                self.last_notify_ts = ts
                sev = str(item.get("severity", "low")).lower()
                if popup_enabled and SEVERITY_ORDER.get(sev, 1) >= SEVERITY_ORDER.get(min_sev, 4):
                    self._notify(item.get("title", "net-monitor"), item.get("message", ""))
                self._append_text(f"ALERT: {item.get('title','')} {item.get('message','')}\n")

        OFFSET_FILE.write_text(str(new_offset), encoding="utf-8")
        return True

    def _notify(self, title: str, message: str) -> None:
        n = Notify.Notification.new(title, message, "dialog-warning")
        n.show()

    def _extract_ips(self, events: List[Dict[str, Any]]) -> List[str]:
        mode = "all"
        if hasattr(self, "ip_filter_combo") and self.ip_filter_combo is not None:
            mode = (self.ip_filter_combo.get_active_text() or "all").strip().lower()

        ips = set()
        for ev in events:
            src = str(ev.get("src_ip", "")).strip()
            dst = str(ev.get("dst_ip", "")).strip()
            sev = str(ev.get("severity", "low")).lower()
            has_alert = bool(ev.get("issues")) or sev in ("medium", "high", "critical")

            for ip in (src, dst):
                if not ip or ip == "-":
                    continue
                if mode == "with alerts" and not has_alert:
                    continue
                if mode == "local only" and not self._is_local_ip(ip):
                    continue
                if mode == "external only" and self._is_local_ip(ip):
                    continue
                ips.add(ip)
        return sorted(ips)

    def _guess_device_for_ip(self, events: List[Dict[str, Any]], ip: str) -> str:
        hints: Dict[str, int] = {}
        for ev in events[-500:]:
            src = str(ev.get("src_ip", "")).strip()
            dst = str(ev.get("dst_ip", "")).strip()
            if ip not in {src, dst}:
                continue
            ports = {
                int(ev.get("src_port", 0) or 0),
                int(ev.get("dst_port", 0) or 0),
            }
            http = ev.get("http", {}) if isinstance(ev.get("http"), dict) else {}
            ua = str(http.get("user_agent", "")).lower()

            if any(p in ports for p in (554, 8554, 8000, 8081)):
                hints["camera/iot"] = hints.get("camera/iot", 0) + 2
            if any(p in ports for p in (1883, 8883, 5683)):
                hints["iot/sensor"] = hints.get("iot/sensor", 0) + 2
            if any(p in ports for p in (9100, 515, 631)):
                hints["printer"] = hints.get("printer", 0) + 2
            if any(p in ports for p in (3389, 445, 139)):
                hints["windows-host"] = hints.get("windows-host", 0) + 2
            if any(p in ports for p in (22, 2375, 2376, 6443)):
                hints["server"] = hints.get("server", 0) + 1
            if "android" in ua:
                hints["android-device"] = hints.get("android-device", 0) + 3
            if "iphone" in ua or "ipad" in ua or "ios" in ua:
                hints["ios-device"] = hints.get("ios-device", 0) + 3
            if "windows" in ua:
                hints["windows-host"] = hints.get("windows-host", 0) + 1
            if "mac os" in ua or "macintosh" in ua:
                hints["mac-device"] = hints.get("mac-device", 0) + 1

        if not hints:
            return "unknown"
        return sorted(hints.items(), key=lambda x: x[1], reverse=True)[0][0]

    def _is_local_ip(self, ip: str) -> bool:
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return bool(obj.is_private or obj.is_loopback or obj.is_link_local)

    def _refresh_ip_store(self, events: List[Dict[str, Any]]) -> None:
        if self.ip_store is None:
            return
        selected_ip = ""
        prev_scroll = self._capture_vscroll(getattr(self, "ip_scroll", None))
        if hasattr(self, "ip_tree") and self.ip_tree is not None:
            model, tree_iter = self.ip_tree.get_selection().get_selected()
            if tree_iter is not None:
                selected_ip = str(model.get_value(tree_iter, 0))

        ips = self._extract_ips(events)
        self.ip_store.clear()
        for ip in ips:
            self.ip_store.append([ip, self._guess_device_for_ip(events, ip)])

        if hasattr(self, "scan_target_combo"):
            current_target = self._combo_text(self.scan_target_combo)
            self._rebuild_combo_options(self.scan_target_combo, ips, "Select or type IP")
            self._set_combo_text(self.scan_target_combo, current_target)

        if selected_ip and hasattr(self, "ip_tree"):
            it = self.ip_store.get_iter_first()
            while it is not None:
                if str(self.ip_store.get_value(it, 0)) == selected_ip:
                    self.ip_tree.get_selection().select_iter(it)
                    break
                it = self.ip_store.iter_next(it)
        self._restore_vscroll(getattr(self, "ip_scroll", None), prev_scroll)

    def _rebuild_combo_options(self, combo: Gtk.ComboBoxText, options: List[str], placeholder: str) -> None:
        seen = set()
        combo.remove_all()
        for opt in options:
            val = str(opt).strip()
            if not val or val in seen:
                continue
            combo.append_text(val)
            seen.add(val)
        child = combo.get_child()
        if isinstance(child, Gtk.Entry):
            child.set_placeholder_text(placeholder)

    def _on_open_ip_window(self, _btn) -> None:
        if self.ip_window is None:
            self.ip_window = Gtk.Window(title="Observed IP addresses")
            self.ip_window.set_default_size(760, 560)
            self.ip_window.connect("delete-event", self._on_ip_window_delete)

            outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            outer.set_border_width(10)

            filter_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            filter_row.pack_start(Gtk.Label(label="IP filter"), False, False, 0)
            self.ip_filter_combo = Gtk.ComboBoxText()
            for val in ["all", "local only", "external only", "with alerts"]:
                self.ip_filter_combo.append_text(val)
            self.ip_filter_combo.set_active(0)
            self.ip_filter_combo.connect("changed", self._on_ip_filter_changed)
            filter_row.pack_start(self.ip_filter_combo, False, False, 0)
            outer.pack_start(filter_row, False, False, 0)

            self.ip_store = Gtk.ListStore(str, str)
            tree = Gtk.TreeView(model=self.ip_store)
            renderer = Gtk.CellRendererText()
            tree.append_column(Gtk.TreeViewColumn("IP address", renderer, text=0))
            tree.append_column(Gtk.TreeViewColumn("Device", renderer, text=1))
            tree.get_selection().connect("changed", self._on_ip_selected)
            self.ip_tree = tree

            scroll = Gtk.ScrolledWindow()
            scroll.add(tree)
            self.ip_scroll = scroll
            outer.pack_start(scroll, True, True, 0)

            self.scan_target_combo = self._combo_with_entry([], "Select or type IP/host/URL")
            outer.pack_start(self.scan_target_combo, False, False, 0)

            use_selected_btn = Gtk.Button(label="Use selected IP")
            use_selected_btn.connect("clicked", self._on_use_selected_ip)
            outer.pack_start(use_selected_btn, False, False, 0)

            self.scan_profile_combo = Gtk.ComboBoxText()
            self.scan_profile_combo.append_text("quick")
            self.scan_profile_combo.append_text("dns")
            self.scan_profile_combo.append_text("port-top100")
            self.scan_profile_combo.append_text("port-top1000")
            self.scan_profile_combo.append_text("full")
            self.scan_profile_combo.append_text("service-fingerprint")
            self.scan_profile_combo.append_text("tls-endpoint")
            self.scan_profile_combo.append_text("dns-hygiene")
            self.scan_profile_combo.append_text("url-scan")
            self.scan_profile_combo.append_text("vuln-audit")
            self.scan_profile_combo.set_active(0)
            self.scan_profile_combo.connect("changed", self._on_scan_profile_changed)
            outer.pack_start(self.scan_profile_combo, False, False, 0)

            self.scan_ports_entry = Gtk.Entry()
            self.scan_ports_entry.set_placeholder_text("Full scan ports, e.g. 1-1024,80,443")
            self.scan_ports_entry.set_sensitive(False)
            outer.pack_start(self.scan_ports_entry, False, False, 0)

            self.scan_scripts_entry = Gtk.Entry()
            self.scan_scripts_entry.set_placeholder_text("Full scan scripts, e.g. default,vuln")
            self.scan_scripts_entry.set_sensitive(False)
            outer.pack_start(self.scan_scripts_entry, False, False, 0)

            self.scan_btn = Gtk.Button(label="Run scan")
            self.scan_btn.connect("clicked", self._on_run_ip_scan)
            outer.pack_start(self.scan_btn, False, False, 0)

            self.scan_cancel_btn = Gtk.Button(label="Cancel scan")
            self.scan_cancel_btn.connect("clicked", self._on_cancel_ip_scan)
            self.scan_cancel_btn.set_sensitive(False)
            outer.pack_start(self.scan_cancel_btn, False, False, 0)

            self.scan_progress = Gtk.ProgressBar()
            self.scan_progress.set_show_text(True)
            self.scan_progress.set_text("Idle")
            outer.pack_start(self.scan_progress, False, False, 0)

            self.scan_status_label = Gtk.Label(label="Scan status: idle")
            self.scan_status_label.set_xalign(0)
            outer.pack_start(self.scan_status_label, False, False, 0)

            self.scan_output = Gtk.TextView()
            self.scan_output.set_editable(False)
            self.scan_output.set_monospace(True)
            self.scan_output_buffer = self.scan_output.get_buffer()
            out_scroll = Gtk.ScrolledWindow()
            out_scroll.set_min_content_height(160)
            out_scroll.add(self.scan_output)
            outer.pack_start(out_scroll, True, True, 0)

            self.scan_history_store = Gtk.ListStore(str, str, str, str, str)
            history_tree = Gtk.TreeView(model=self.scan_history_store)
            for idx, title in enumerate(["Time", "Target", "Profile", "Status"]):
                hr = Gtk.CellRendererText()
                history_tree.append_column(Gtk.TreeViewColumn(title, hr, text=idx))
            history_tree.get_selection().connect("changed", self._on_scan_history_selected)
            self.scan_history_tree = history_tree
            history_scroll = Gtk.ScrolledWindow()
            history_scroll.set_min_content_height(140)
            history_scroll.add(history_tree)
            outer.pack_start(Gtk.Label(label=self._t("scan_history")), False, False, 0)
            outer.pack_start(history_scroll, True, True, 0)

            self.ip_window.add(outer)

        self._refresh_ip_store(self._events_cache)
        self._refresh_scan_history_view()
        self.ip_window.show_all()
        self.ip_window.present()

    def _on_ip_window_delete(self, _win, _event):
        if self.ip_window is not None:
            self.ip_window.hide()
        return True

    def _on_ip_selected(self, selection) -> None:
        model, tree_iter = selection.get_selected()
        if tree_iter is None:
            return

    def _on_use_selected_ip(self, _btn) -> None:
        if not hasattr(self, "ip_tree"):
            return
        model, tree_iter = self.ip_tree.get_selection().get_selected()
        if tree_iter is None:
            return
        ip = str(model.get_value(tree_iter, 0))
        if hasattr(self, "scan_target_combo"):
            self._set_combo_text(self.scan_target_combo, ip)

    def _on_ip_filter_changed(self, _combo) -> None:
        self._refresh_ip_store(self._events_cache)

    def _on_scan_profile_changed(self, _combo) -> None:
        profile = (self.scan_profile_combo.get_active_text() or "quick").strip().lower()
        full = profile == "full"
        self.scan_ports_entry.set_sensitive(full)
        self.scan_scripts_entry.set_sensitive(full)

    def _refresh_scan_history_view(self) -> None:
        if not hasattr(self, "scan_history_store"):
            return
        self.scan_history_store.clear()
        items = list(reversed(read_scan_history(SCAN_HISTORY, limit=60)))
        for item in items:
            ts = int(item.get("finished_ts", item.get("started_ts", 0)) or 0)
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"
            self.scan_history_store.append([
                ts_str,
                str(item.get("target", "-")),
                str(item.get("profile", "-")),
                str(item.get("status", "-")),
                json.dumps(item, ensure_ascii=False),
            ])
        if items:
            last = items[0]
            self._show_scan_result(last, mark_restored=False)

    def _show_scan_result(self, result: Dict[str, Any], mark_restored: bool = False) -> None:
        if not hasattr(self, "scan_output_buffer"):
            return
        cmd = result.get("command", [])
        cmd_text = " ".join([str(x) for x in cmd]) if isinstance(cmd, list) else str(cmd or "")
        header = (
            f"target={result.get('target')} profile={result.get('profile')} "
            f"status={result.get('status')} rc={result.get('return_code')}\n"
            f"command={cmd_text}\n\n"
        )
        body = str(result.get("output", ""))
        if mark_restored:
            body = f"[{self._t('scan_restored')}]\n\n" + body
        self.scan_output_buffer.set_text(header + body)

    def _on_scan_history_selected(self, selection) -> None:
        model, tree_iter = selection.get_selected()
        if tree_iter is None:
            return
        raw = str(model.get_value(tree_iter, 4) or "")
        if not raw:
            return
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return
        if isinstance(payload, dict):
            self._show_scan_result(payload, mark_restored=True)

    def _on_run_ip_scan(self, _btn) -> None:
        if self._scan_in_progress:
            self.scan_output_buffer.set_text("Scan is already running. Please wait.")
            return

        target = self._combo_text(self.scan_target_combo) if hasattr(self, "scan_target_combo") else ""
        profile = (self.scan_profile_combo.get_active_text() or "quick").strip().lower()
        ports = self.scan_ports_entry.get_text().strip() if hasattr(self, "scan_ports_entry") else ""
        scripts = self.scan_scripts_entry.get_text().strip() if hasattr(self, "scan_scripts_entry") else ""
        if not target:
            self.scan_output_buffer.set_text("Select or enter IP/host/URL first")
            return

        self._scan_in_progress = True
        self._scan_started_ts = time.time()
        self.scan_btn.set_sensitive(False)
        if hasattr(self, "scan_cancel_btn"):
            self.scan_cancel_btn.set_sensitive(True)
        if hasattr(self, "scan_progress"):
            self.scan_progress.set_fraction(0.0)
            self.scan_progress.set_text("Running...")
        if hasattr(self, "scan_status_label"):
            self.scan_status_label.set_text("Scan status: running")
        self.scan_output_buffer.set_text(f"Running {profile} scan for {target}...\n")

        started = self.scan_backend.start_scan(
            target=target,
            profile=profile,
            ports=ports,
            scripts=scripts,
            callback=lambda result: GLib.idle_add(self._on_scan_finished_ui, result),
            progress_callback=lambda payload: GLib.idle_add(self._on_scan_progress_ui, payload),
        )
        if not started:
            self._scan_in_progress = False
            self.scan_btn.set_sensitive(True)
            if hasattr(self, "scan_cancel_btn"):
                self.scan_cancel_btn.set_sensitive(False)
            if hasattr(self, "scan_status_label"):
                self.scan_status_label.set_text("Scan status: another scan is already running")

    def _on_cancel_ip_scan(self, _btn) -> None:
        cancelled = self.scan_backend.cancel_scan()
        if cancelled:
            if hasattr(self, "scan_status_label"):
                self.scan_status_label.set_text("Scan status: cancelling...")
            if hasattr(self, "scan_progress"):
                self.scan_progress.set_text("Cancelling...")
            end = self.scan_output_buffer.get_end_iter()
            self.scan_output_buffer.insert(end, "\nCancellation requested...\n")

    def _refresh_scan_progress(self) -> bool:
        if not self._scan_in_progress:
            return True
        if hasattr(self, "scan_progress"):
            self.scan_progress.pulse()
            elapsed = max(0, int(time.time() - self._scan_started_ts)) if self._scan_started_ts else 0
            self.scan_progress.set_text(f"Running... {elapsed}s")
        if hasattr(self, "scan_status_label"):
            elapsed = max(0, int(time.time() - self._scan_started_ts)) if self._scan_started_ts else 0
            self.scan_status_label.set_text(f"Scan status: in progress ({elapsed}s)")
        return True

    def _on_scan_progress_ui(self, payload: Dict[str, Any]) -> bool:
        message = str(payload.get("message", "")).strip()
        if message and hasattr(self, "scan_output_buffer"):
            end = self.scan_output_buffer.get_end_iter()
            self.scan_output_buffer.insert(end, f"[scan] {message}\n")

        status = str(payload.get("status", "")).strip().lower()
        if hasattr(self, "scan_status_label") and status:
            if status == "finished":
                result_status = str(payload.get("result_status", "ok"))
                self.scan_status_label.set_text(f"Scan status: finished ({result_status})")
            else:
                self.scan_status_label.set_text(f"Scan status: {status}")
        return False

    def _on_scan_finished_ui(self, result: Dict[str, Any]) -> bool:
        self._scan_in_progress = False
        self._scan_started_ts = 0.0
        self.scan_btn.set_sensitive(True)
        if hasattr(self, "scan_cancel_btn"):
            self.scan_cancel_btn.set_sensitive(False)
        if hasattr(self, "scan_progress"):
            self.scan_progress.set_fraction(0.0)
            status = str(result.get("status", "ok"))
            self.scan_progress.set_text(f"Done ({status})")
        if hasattr(self, "scan_status_label"):
            self.scan_status_label.set_text(f"Scan status: {result.get('status', 'ok')}")
        self._show_scan_result(result, mark_restored=False)
        self._refresh_scan_history_view()
        return False


def main() -> None:
    NetMonitorTray()
    Gtk.main()


if __name__ == "__main__":
    main()
