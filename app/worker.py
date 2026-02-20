from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime

from app.models import CollectorState, CollectorTarget, Event, Severity
from app.services import MonitoringService


@dataclass
class ProbeResult:
    ok: bool
    latency_ms: float | None
    message: str


class AgentlessWorker:
    def __init__(self, service: MonitoringService, tick_sec: float = 2.0, timeout_sec: float = 2.0) -> None:
        self.service = service
        self.tick_sec = tick_sec
        self.timeout_sec = timeout_sec
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_run_at: dict[str, float] = {}
        self._cycle_count = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="agentless-worker")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def status(self) -> dict:
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "tick_sec": self.tick_sec,
            "timeout_sec": self.timeout_sec,
            "cycle_count": self._cycle_count,
            "targets_tracked": len(self.service.list_collector_targets()),
        }

    def target_status(self) -> list[dict]:
        rows = []
        for target in self.service.list_collector_targets():
            state = self.service.get_collector_state(target.id)
            rows.append(
                {
                    "target_id": target.id,
                    "name": target.name,
                    "collector_type": target.collector_type.value,
                    "address": target.address,
                    "port": target.port,
                    "enabled": target.enabled,
                    "last_ok": state.last_error is None and state.last_run_ts is not None,
                    "last_message": state.last_error or "ok",
                    "last_run_ts": state.last_run_ts,
                    "last_success_ts": state.last_success_ts,
                    "last_cursor": state.last_cursor,
                    "failure_streak": state.failure_streak,
                }
            )
        return rows

    def run_once(self) -> int:
        accepted = 0
        now = time.time()
        self._cycle_count += 1

        for target in self.service.list_collector_targets():
            if not target.enabled:
                continue

            last = self._last_run_at.get(target.id, 0)
            if now - last < target.poll_interval_sec:
                continue

            self._last_run_at[target.id] = now
            events, state = self._collect_target(target)
            for event in events:
                _, inserted = self.service.register_event(event)
                if inserted:
                    accepted += 1
            self.service.upsert_collector_state(state)
        return accepted

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.run_once()
            except Exception:
                pass
            self._stop_event.wait(self.tick_sec)

    def _collect_target(self, target: CollectorTarget) -> tuple[list[Event], CollectorState]:
        if target.collector_type.value == "winrm":
            return self._collect_winrm_target(target)
        if target.collector_type.value == "ssh":
            return self._collect_ssh_target(target)
        return self._collect_snmp_target(target)

    def _collect_winrm_target(self, target: CollectorTarget) -> tuple[list[Event], CollectorState]:
        prev = self.service.get_collector_state(target.id)
        current_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        try:
            records, next_cursor = self._pull_winrm_records(target, prev.last_cursor)
        except Exception as exc:
            streak = prev.failure_streak + 1
            state = CollectorState(
                target_id=target.id,
                last_success_ts=prev.last_success_ts,
                last_run_ts=current_ts,
                last_error=f"winrm pull failed: {exc}",
                last_cursor=prev.last_cursor,
                failure_streak=streak,
            )
            severity = Severity.critical if streak >= 3 else Severity.warning
            return (
                [
                    Event(
                        asset_id=target.asset_id,
                        source="agentless_winrm",
                        message=f"[winrm] pull failed for '{target.name}': {exc}",
                        metric="collector_failure_streak",
                        value=float(streak),
                        severity=severity,
                    )
                ],
                state,
            )

        events: list[Event] = []
        for row in records:
            lvl = (row.get("LevelDisplayName") or "").lower()
            sev = Severity.info
            if "warning" in lvl or "error" in lvl:
                sev = Severity.warning
            if "critical" in lvl:
                sev = Severity.critical

            msg = row.get("Message") or "(no message)"
            events.append(
                Event(
                    asset_id=target.asset_id,
                    source="windows_eventlog",
                    message=(
                        f"[{row.get('LogName', 'Unknown')}] EventID={row.get('Id', 'Unknown')} "
                        f"RecordId={row.get('RecordId', 'Unknown')} Provider={row.get('ProviderName', 'Unknown')} :: {msg}"
                    ),
                    severity=sev,
                )
            )

        if not events:
            events.append(
                Event(
                    asset_id=target.asset_id,
                    source="agentless_winrm",
                    message=f"[winrm] no new events for '{target.name}', cursor={next_cursor}",
                    severity=Severity.info,
                )
            )

        state = CollectorState(
            target_id=target.id,
            last_success_ts=current_ts,
            last_run_ts=current_ts,
            last_error=None,
            last_cursor=next_cursor,
            failure_streak=0,
        )
        return events, state

    def _collect_ssh_target(self, target: CollectorTarget) -> tuple[list[Event], CollectorState]:
        return self._collect_probe_target(target, "ssh")

    def _collect_snmp_target(self, target: CollectorTarget) -> tuple[list[Event], CollectorState]:
        return self._collect_probe_target(target, "snmp")

    def _collect_probe_target(self, target: CollectorTarget, proto: str) -> tuple[list[Event], CollectorState]:
        result = self._probe_tcp(target.address, target.port, self.timeout_sec)
        prev = self.service.get_collector_state(target.id)
        current_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        if result.ok:
            state = CollectorState(
                target_id=target.id,
                last_success_ts=current_ts,
                last_run_ts=current_ts,
                last_error=None,
                last_cursor=prev.last_cursor,
                failure_streak=0,
            )
            return (
                [
                    Event(
                        asset_id=target.asset_id,
                        source=f"agentless_{proto}",
                        message=f"[{proto}] target '{target.name}' reachable at {target.address}:{target.port}. {result.message}",
                        metric="collector_latency_ms",
                        value=result.latency_ms,
                        severity=Severity.info,
                    )
                ],
                state,
            )

        streak = prev.failure_streak + 1
        state = CollectorState(
            target_id=target.id,
            last_success_ts=prev.last_success_ts,
            last_run_ts=current_ts,
            last_error=result.message,
            last_cursor=prev.last_cursor,
            failure_streak=streak,
        )
        severity = Severity.critical if streak >= 3 else Severity.warning
        return (
            [
                Event(
                    asset_id=target.asset_id,
                    source=f"agentless_{proto}",
                    message=(
                        f"[{proto}] target '{target.name}' unreachable at {target.address}:{target.port}. "
                        f"{result.message}. failure_streak={streak}"
                    ),
                    metric="collector_failure_streak",
                    value=float(streak),
                    severity=severity,
                )
            ],
            state,
        )

    def _pull_winrm_records(self, target: CollectorTarget, last_cursor: str | None) -> tuple[list[dict], str]:
        try:
            import winrm  # type: ignore
        except ImportError as exc:
            raise RuntimeError("pywinrm is not installed") from exc

        cursor = int(last_cursor) if (last_cursor and str(last_cursor).isdigit()) else 0
        ps = f"""
$last = {cursor}
$events = Get-WinEvent -FilterHashtable @{{LogName=@('System','Application')}} -ErrorAction SilentlyContinue |
    Where-Object {{ $_.RecordId -gt $last }} |
    Select-Object -First 50 RecordId,Id,LogName,ProviderName,LevelDisplayName,TimeCreated,Message
$events | ConvertTo-Json -Depth 4 -Compress
"""
        endpoint = f"http://{target.address}:{target.port}/wsman"
        session = winrm.Session(endpoint, auth=(target.username, target.password), transport="ntlm")
        result = session.run_ps(ps)
        if result.status_code != 0:
            err = (result.std_err or b"").decode("utf-8", errors="ignore")
            raise RuntimeError(f"WinRM command failed: {err.strip() or 'unknown error'}")

        stdout = (result.std_out or b"").decode("utf-8", errors="ignore").strip()
        if not stdout:
            return [], str(cursor)

        parsed = json.loads(stdout)
        rows = parsed if isinstance(parsed, list) else [parsed]
        max_cursor = cursor
        for row in rows:
            try:
                max_cursor = max(max_cursor, int(row.get("RecordId", cursor)))
            except Exception:
                pass

        return rows, str(max_cursor)

    @staticmethod
    def _probe_tcp(host: str, port: int, timeout_sec: float) -> ProbeResult:
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        try:
            sock.connect((host, port))
            latency = round((time.perf_counter() - start) * 1000, 2)
            return ProbeResult(ok=True, latency_ms=latency, message="TCP probe ok")
        except OSError as exc:
            return ProbeResult(ok=False, latency_ms=None, message=f"TCP probe failed: {exc}")
        finally:
            sock.close()
