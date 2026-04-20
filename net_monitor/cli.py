#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess

from .daemon import run_daemon


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="net-monitor command entrypoint")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("daemon", help="Run passive monitoring daemon")
    d.add_argument("--config", default=None)
    d.add_argument("--home", default=None)

    m = sub.add_parser("monitor", help="Run normal terminal monitoring mode")
    m.add_argument("--config", default=None)
    m.add_argument("--home", default=None)

    sub.add_parser("tray", help="Run tray indicator application")
    f = sub.add_parser("full", help="Run daemon + tray in one terminal (development mode)")
    f.add_argument("--config", default=None)
    f.add_argument("--home", default=None)
    return p


def main() -> None:
    args = build_parser().parse_args()
    if args.cmd == "daemon":
        run_daemon(config_path=args.config, home_path=args.home)
    elif args.cmd == "monitor":
        run_daemon(config_path=args.config, home_path=args.home)
    elif args.cmd == "tray":
        from .tray import main as tray_main

        tray_main()
    elif args.cmd == "full":
        daemon_cmd = ["python3", "-m", "net_monitor", "daemon"]
        if args.config:
            daemon_cmd.extend(["--config", args.config])
        if args.home:
            daemon_cmd.extend(["--home", args.home])
        daemon_proc = subprocess.Popen(daemon_cmd)  # noqa: S603
        try:
            from .tray import main as tray_main

            tray_main()
        finally:
            daemon_proc.terminate()


if __name__ == "__main__":
    main()
