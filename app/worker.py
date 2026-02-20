from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass

from app.models import CollectorTarget, Event, Severity
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
        self._last_result: dict[str, dict[str, str | int | float | bool | None]] = {}
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
            "targets_tracked": len(self._last_result),
        }

    def target_status(self) -> list[dict]:
        rows = []
        for target in self.service.list_collector_targets():
            state = self._last_result.get(target.id, {})
            rows.append(
                {
                    "target_id": target.id,
                    "name": target.name,
                    "collector_type": target.collector_type.value,
                    "address": target.address,
                    "port": target.port,
                    "enabled": target.enabled,
                    "last_ok": state.get("ok"),
                    "last_latency_ms": state.get("latency_ms"),
                    "last_message": state.get("message"),
                    "last_run_ts": state.get("run_ts"),
                    "failure_streak": state.get("failure_streak", 0),
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
            event = self._collect_target(target)
            self.service.register_event(event)
            accepted += 1
        return accepted

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.run_once()
            except Exception:
                pass
            self._stop_event.wait(self.tick_sec)

    def _collect_target(self, target: CollectorTarget) -> Event:
        result = self._probe_tcp(target.address, target.port, self.timeout_sec)
        source = f"agentless_{target.collector_type.value}"

        prev = self._last_result.get(target.id, {})
        prev_streak = int(prev.get("failure_streak", 0))
        streak = 0 if result.ok else prev_streak + 1

        self._last_result[target.id] = {
            "ok": result.ok,
            "latency_ms": result.latency_ms,
            "message": result.message,
            "run_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "failure_streak": streak,
        }

        if result.ok:
            return Event(
                asset_id=target.asset_id,
                source=source,
                message=f"Collector target '{target.name}' reachable at {target.address}:{target.port}. {result.message}",
                metric="collector_latency_ms",
                value=result.latency_ms,
                severity=Severity.info,
            )

        severity = Severity.critical if streak >= 3 else Severity.warning
        return Event(
            asset_id=target.asset_id,
            source=source,
            message=(
                f"Collector target '{target.name}' unreachable at {target.address}:{target.port}. "
                f"{result.message}. failure_streak={streak}"
            ),
            metric="collector_failure_streak",
            value=float(streak),
            severity=severity,
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
