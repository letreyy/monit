from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass

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
            event, state = self._collect_target(target)
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

    def _collect_target(self, target: CollectorTarget) -> tuple[Event, CollectorState]:
        if target.collector_type.value == "winrm":
            return self._collect_winrm_target(target)
        if target.collector_type.value == "ssh":
            return self._collect_ssh_target(target)
        return self._collect_snmp_target(target)

    def _next_cursor(self, prev: CollectorState) -> str:
        try:
            base = int(prev.last_cursor) if prev.last_cursor else 0
        except ValueError:
            base = 0
        return str(base + 1)

    def _collect_winrm_target(self, target: CollectorTarget) -> tuple[Event, CollectorState]:
        return self._collect_generic_target(target, "winrm")

    def _collect_ssh_target(self, target: CollectorTarget) -> tuple[Event, CollectorState]:
        return self._collect_generic_target(target, "ssh")

    def _collect_snmp_target(self, target: CollectorTarget) -> tuple[Event, CollectorState]:
        return self._collect_generic_target(target, "snmp")

    def _collect_generic_target(self, target: CollectorTarget, proto: str) -> tuple[Event, CollectorState]:
        result = self._probe_tcp(target.address, target.port, self.timeout_sec)
        source = f"agentless_{proto}"
        prev = self.service.get_collector_state(target.id)
        current_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        next_cursor = self._next_cursor(prev)

        if result.ok:
            state = CollectorState(
                target_id=target.id,
                last_success_ts=current_ts,
                last_run_ts=current_ts,
                last_error=None,
                last_cursor=next_cursor,
                failure_streak=0,
            )
            return (
                Event(
                    asset_id=target.asset_id,
                    source=source,
                    message=(
                        f"[{proto}] target '{target.name}' reachable at {target.address}:{target.port}. "
                        f"{result.message}; cursor={next_cursor}"
                    ),
                    metric="collector_latency_ms",
                    value=result.latency_ms,
                    severity=Severity.info,
                ),
                state,
            )

        streak = prev.failure_streak + 1
        state = CollectorState(
            target_id=target.id,
            last_success_ts=prev.last_success_ts,
            last_run_ts=current_ts,
            last_error=result.message,
            last_cursor=next_cursor,
            failure_streak=streak,
        )
        severity = Severity.critical if streak >= 3 else Severity.warning
        return (
            Event(
                asset_id=target.asset_id,
                source=source,
                message=(
                    f"[{proto}] target '{target.name}' unreachable at {target.address}:{target.port}. "
                    f"{result.message}. failure_streak={streak}; cursor={next_cursor}"
                ),
                metric="collector_failure_streak",
                value=float(streak),
                severity=severity,
            ),
            state,
        )

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
