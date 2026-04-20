from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


class IPScanBackend:
    def __init__(self, history_path: Path) -> None:
        self.history_path = history_path
        self._lock = threading.Lock()
        self._current_proc: Optional[subprocess.Popen[str]] = None
        self._cancel_requested = False
        self._active_scan: Optional[Dict[str, Any]] = None

    def start_scan(
        self,
        target: str,
        profile: str,
        ports: str,
        scripts: str,
        callback: Callable[[Dict[str, Any]], None],
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> bool:
        with self._lock:
            if self._active_scan is not None:
                return False
            self._cancel_requested = False
            self._active_scan = {
                "target": target,
                "profile": profile,
                "started_ts": int(time.time()),
            }
        t = threading.Thread(
            target=self._worker,
            args=(target, profile, ports, scripts, callback, progress_callback),
            daemon=True,
        )
        t.start()
        return True

    def cancel_scan(self) -> bool:
        with self._lock:
            active = self._active_scan is not None
            self._cancel_requested = True
            proc = self._current_proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
        return active

    def is_scan_active(self) -> bool:
        with self._lock:
            return self._active_scan is not None

    def _worker(
        self,
        target: str,
        profile: str,
        ports: str,
        scripts: str,
        callback: Callable[[Dict[str, Any]], None],
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        started = int(time.time())
        result: Dict[str, Any] = {
            "started_ts": started,
            "target": target,
            "profile": profile,
            "ports": ports,
            "scripts": scripts,
            "status": "ok",
            "return_code": 0,
            "command": [],
            "output": "",
            "cancelled": False,
        }

        self._emit_progress(progress_callback, {
            "status": "started",
            "target": target,
            "profile": profile,
            "started_ts": started,
            "message": f"Scan started: {profile} {target}",
        })

        try:
            output, return_code, cmd, cancelled = self._run_scan(target, profile, ports, scripts, progress_callback)
            result["output"] = output
            result["return_code"] = return_code
            result["command"] = cmd
            result["cancelled"] = cancelled
            if cancelled:
                result["status"] = "cancelled"
            elif return_code != 0:
                result["status"] = "failed"
        except FileNotFoundError as exc:
            result["status"] = "tool_missing"
            result["output"] = f"Missing scanner tool: {exc}"
        except subprocess.TimeoutExpired as exc:
            result["status"] = "timeout"
            cmd = []
            if getattr(exc, "cmd", None):
                if isinstance(exc.cmd, (list, tuple)):
                    cmd = [str(x) for x in exc.cmd]
                else:
                    cmd = [str(exc.cmd)]
            timeout_sec = int(getattr(exc, "timeout", 0) or 0)
            result["command"] = cmd
            cmd_text = " ".join(cmd) if cmd else "unknown"
            result["output"] = f"Scan timed out after {timeout_sec}s\nCommand: {cmd_text}"
        except Exception as exc:
            result["status"] = "error"
            result["output"] = f"Unexpected scan error: {exc}"
        finally:
            with self._lock:
                self._current_proc = None
                self._active_scan = None

        result["finished_ts"] = int(time.time())
        result["duration_sec"] = max(0, result["finished_ts"] - started)
        self._append_history(result)
        self._emit_progress(progress_callback, {
            "status": "finished",
            "target": target,
            "profile": profile,
            "finished_ts": result["finished_ts"],
            "duration_sec": result["duration_sec"],
            "result_status": result.get("status", "ok"),
        })
        callback(result)

    def _emit_progress(self, callback: Optional[Callable[[Dict[str, Any]], None]], payload: Dict[str, Any]) -> None:
        if callback is None:
            return
        try:
            callback(payload)
        except Exception:
            return

    def _profile_timeout(self, profile: str) -> int:
        profile = profile.strip().lower()
        mapping = {
            "quick": 240,
            "dns": 90,
            "dns-hygiene": 240,
            "url-scan": 120,
            "tls-endpoint": 420,
            "service-fingerprint": 900,
            "vuln-audit": 1200,
            "port-top100": 300,
            "port-top1000": 900,
            "full": 1800,
        }
        return int(mapping.get(profile, 300))

    def _run_cmd(self, cmd: List[str], timeout: int = 120) -> tuple[str, int, bool]:
        started = time.time()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        with self._lock:
            self._current_proc = proc

        while True:
            with self._lock:
                cancel = self._cancel_requested

            if cancel:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                return "Scan cancelled by user", 130, True

            if proc.poll() is not None:
                out, err = proc.communicate()
                output = (out or "") + ("\n" + err if err else "")
                return output.strip() or "No output returned", proc.returncode, False

            if (time.time() - started) > timeout:
                try:
                    proc.terminate()
                except Exception:
                    pass
                raise subprocess.TimeoutExpired(cmd, timeout)

            time.sleep(0.2)

    def _run_scan(
        self,
        target: str,
        profile: str,
        ports: str,
        scripts: str,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> tuple[str, int, List[str], bool]:
        profile = profile.strip().lower()
        cmd_timeout = self._profile_timeout(profile)
        if profile == "dns":
            out_chunks: List[str] = []
            all_codes: List[int] = []
            cancelled = False
            dig_cmd = ["dig", "+short", target]
            host_cmd = ["host", target]
            for cmd in (dig_cmd, host_cmd):
                self._emit_progress(progress_callback, {
                    "status": "running",
                    "target": target,
                    "profile": profile,
                    "command": cmd,
                    "message": f"Running: {' '.join(cmd)}",
                })
                chunk, rc, was_cancelled = self._run_cmd(cmd, timeout=cmd_timeout)
                all_codes.append(rc)
                out_chunks.append(f"$ {' '.join(cmd)}\n{chunk.strip()}\n")
                if was_cancelled:
                    cancelled = True
                    break
            if cancelled:
                return "\n".join(out_chunks).strip(), 130, ["dig", "+short", target, "&&", "host", target], True
            rc = 0 if all(code == 0 for code in all_codes) else 1
            return "\n".join(out_chunks).strip(), rc, ["dig", "+short", target, "&&", "host", target], False

        if profile == "dns-hygiene":
            out_chunks: List[str] = []
            all_codes: List[int] = []
            cancelled = False
            cmds = [
                ["dig", "+dnssec", target],
                ["dig", "+trace", target],
                ["host", "-a", target],
            ]
            for cmd in cmds:
                self._emit_progress(progress_callback, {
                    "status": "running",
                    "target": target,
                    "profile": profile,
                    "command": cmd,
                    "message": f"Running: {' '.join(cmd)}",
                })
                chunk, rc, was_cancelled = self._run_cmd(cmd, timeout=cmd_timeout)
                all_codes.append(rc)
                out_chunks.append(f"$ {' '.join(cmd)}\n{chunk.strip()}\n")
                if was_cancelled:
                    cancelled = True
                    break
            if cancelled:
                return "\n".join(out_chunks).strip(), 130, ["dig", "+dnssec", target], True
            rc = 0 if all(code == 0 for code in all_codes) else 1
            return "\n".join(out_chunks).strip(), rc, ["dig", "+dnssec", target], False

        if profile == "url-scan":
            cmds = [
                ["curl", "-I", "-L", "--max-time", "15", target],
            ]
            if target.lower().startswith("https://"):
                host_part = target.split("//", 1)[1].split("/", 1)[0]
                if ":" in host_part:
                    host, port = host_part.split(":", 1)
                else:
                    host, port = host_part, "443"
                cmds.append(["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-brief"])

            out_chunks: List[str] = []
            all_codes: List[int] = []
            cancelled = False
            for cmd in cmds:
                self._emit_progress(progress_callback, {
                    "status": "running",
                    "target": target,
                    "profile": profile,
                    "command": cmd,
                    "message": f"Running: {' '.join(cmd)}",
                })
                chunk, rc, was_cancelled = self._run_cmd(cmd, timeout=cmd_timeout)
                all_codes.append(rc)
                out_chunks.append(f"$ {' '.join(cmd)}\n{chunk.strip()}\n")
                if was_cancelled:
                    cancelled = True
                    break
            if cancelled:
                return "\n".join(out_chunks).strip(), 130, ["curl", "-I", target], True
            rc = 0 if all(code == 0 for code in all_codes) else 1
            return "\n".join(out_chunks).strip(), rc, ["curl", "-I", target], False

        if profile == "tls-endpoint":
            cmd = ["nmap", "-Pn", "-p", "443", "--script", "ssl-cert,ssl-enum-ciphers", target]
            self._emit_progress(progress_callback, {
                "status": "running",
                "target": target,
                "profile": profile,
                "command": cmd,
                "message": f"Running: {' '.join(cmd)}",
            })
            output, rc, cancelled = self._run_cmd(cmd, timeout=cmd_timeout)
            return output, rc, cmd, cancelled

        if profile == "vuln-audit":
            cmd = ["nmap", "-sV", "-Pn", "--script", "vuln", "--script-timeout", "90s", target]
            self._emit_progress(progress_callback, {
                "status": "running",
                "target": target,
                "profile": profile,
                "command": cmd,
                "message": f"Running: {' '.join(cmd)}",
            })
            output, rc, cancelled = self._run_cmd(cmd, timeout=cmd_timeout)
            return output, rc, cmd, cancelled

        if profile == "service-fingerprint":
            cmd = ["nmap", "-sV", "--version-all", "-Pn", target]
            self._emit_progress(progress_callback, {
                "status": "running",
                "target": target,
                "profile": profile,
                "command": cmd,
                "message": f"Running: {' '.join(cmd)}",
            })
            output, rc, cancelled = self._run_cmd(cmd, timeout=cmd_timeout)
            return output, rc, cmd, cancelled

        if profile == "port-top100":
            cmd = ["nmap", "--top-ports", "100", "-Pn", target]
            self._emit_progress(progress_callback, {
                "status": "running",
                "target": target,
                "profile": profile,
                "command": cmd,
                "message": f"Running: {' '.join(cmd)}",
            })
            output, rc, cancelled = self._run_cmd(cmd, timeout=cmd_timeout)
            return output, rc, cmd, cancelled

        if profile == "port-top1000":
            cmd = ["nmap", "--top-ports", "1000", "-Pn", target]
            self._emit_progress(progress_callback, {
                "status": "running",
                "target": target,
                "profile": profile,
                "command": cmd,
                "message": f"Running: {' '.join(cmd)}",
            })
            output, rc, cancelled = self._run_cmd(cmd, timeout=cmd_timeout)
            return output, rc, cmd, cancelled

        if profile == "full":
            base_cmd = ["nmap", "-sV", "-sC", "-Pn"]
            if ports.strip():
                base_cmd.extend(["-p", ports.strip()])
            if scripts.strip():
                base_cmd.extend(["--script", scripts.strip()])
            base_cmd.append(target)

            privileged_cmd = ["pkexec", "nmap", "-sV", "-sC", "-O", "-Pn"]
            if ports.strip():
                privileged_cmd.extend(["-p", ports.strip()])
            if scripts.strip():
                privileged_cmd.extend(["--script", scripts.strip()])
            privileged_cmd.append(target)

            try:
                self._emit_progress(progress_callback, {
                    "status": "running",
                    "target": target,
                    "profile": profile,
                    "command": privileged_cmd,
                    "message": f"Running privileged full scan: {' '.join(privileged_cmd)}",
                })
                output, rc, cancelled = self._run_cmd(privileged_cmd, timeout=cmd_timeout)
                if cancelled:
                    return output, rc, privileged_cmd, True

                lower_out = output.lower()
                auth_or_perm_error = (
                    "operation not permitted" in lower_out
                    or "requires root privileges" in lower_out
                    or "you requested a scan type which requires root privileges" in lower_out
                    or "not authorized" in lower_out
                    or rc in (126, 127)
                )
                if auth_or_perm_error:
                    self._emit_progress(progress_callback, {
                        "status": "running",
                        "target": target,
                        "profile": profile,
                        "command": base_cmd,
                        "message": f"Privilege-limited fallback: {' '.join(base_cmd)}",
                    })
                    fallback_out, fallback_rc, fallback_cancelled = self._run_cmd(base_cmd, timeout=cmd_timeout)
                    merged = (
                        output
                        + "\n\n--- fallback without -O ---\n"
                        + fallback_out
                        + "\n\nNote: full privileged scan failed or was restricted; used non-OS fallback."
                    )
                    return merged.strip(), fallback_rc, base_cmd, fallback_cancelled

                return output, rc, privileged_cmd, False
            except FileNotFoundError:
                self._emit_progress(progress_callback, {
                    "status": "running",
                    "target": target,
                    "profile": profile,
                    "command": base_cmd,
                    "message": "pkexec is not available, running non-privileged fallback.",
                })
                output, rc, cancelled = self._run_cmd(base_cmd, timeout=cmd_timeout)
                output += "\n\npkexec is not available; install policykit to allow password prompt for privileged full scan."
                return output.strip(), rc, base_cmd, cancelled
        else:
            cmd = ["nmap", "-F", "-Pn", target]

        self._emit_progress(progress_callback, {
            "status": "running",
            "target": target,
            "profile": profile,
            "command": cmd,
            "message": f"Running: {' '.join(cmd)}",
        })
        output, rc, cancelled = self._run_cmd(cmd, timeout=cmd_timeout)
        return output, rc, cmd, cancelled

    def _append_history(self, entry: Dict[str, Any]) -> None:
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        with self.history_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_scan_history(history_path: Path, limit: int = 100) -> List[Dict[str, Any]]:
    if not history_path.exists():
        return []
    out: List[Dict[str, Any]] = []
    try:
        lines = history_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []

    for line in lines[-limit:]:
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
