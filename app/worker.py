from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime

from app.models import CollectorState, CollectorTarget, Event, Severity, WorkerHistoryEntry
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


    def history(
        self,
        limit: int = 100,
        target_id: str | None = None,
        collector_type: str | None = None,
        has_error: bool | None = None,
    ) -> list[dict]:
        return [
            e.model_dump()
            for e in self.service.list_worker_history(
                limit=limit,
                target_id=target_id,
                collector_type=collector_type,
                has_error=has_error,
            )
        ]

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
            self.service.add_worker_history(
                WorkerHistoryEntry(
                    ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    target_id=target.id,
                    collector_type=target.collector_type.value,
                    accepted_events=len(events),
                    last_error=state.last_error,
                    failure_streak=state.failure_streak,
                    last_cursor=state.last_cursor,
                )
            )
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
        prev = self.service.get_collector_state(target.id)
        current_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        try:
            rows, next_cursor = self._pull_ssh_snapshot(target, prev.last_cursor)
        except Exception as exc:
            streak = prev.failure_streak + 1
            state = CollectorState(
                target_id=target.id,
                last_success_ts=prev.last_success_ts,
                last_run_ts=current_ts,
                last_error=f"ssh pull failed: {exc}",
                last_cursor=prev.last_cursor,
                failure_streak=streak,
            )
            severity = Severity.critical if streak >= 3 else Severity.warning
            return (
                [
                    Event(
                        asset_id=target.asset_id,
                        source="agentless_ssh",
                        message=f"[ssh] pull failed for '{target.name}': {exc}",
                        metric="collector_failure_streak",
                        value=float(streak),
                        severity=severity,
                    )
                ],
                state,
            )

        events: list[Event] = []
        for row in rows:
            if row.get("kind") == "metric":
                events.append(
                    Event(
                        asset_id=target.asset_id,
                        source="ssh_metrics",
                        message=row.get("message", "ssh metric"),
                        metric=row.get("metric"),
                        value=row.get("value"),
                        severity=Severity.info,
                    )
                )
            else:
                events.append(
                    Event(
                        asset_id=target.asset_id,
                        source="ssh_log",
                        message=row.get("message", "ssh log line"),
                        severity=Severity.info,
                    )
                )

        if not events:
            events.append(
                Event(
                    asset_id=target.asset_id,
                    source="agentless_ssh",
                    message=f"[ssh] no new data for '{target.name}', cursor={next_cursor}",
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

    def _collect_snmp_target(self, target: CollectorTarget) -> tuple[list[Event], CollectorState]:
        prev = self.service.get_collector_state(target.id)
        current_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        try:
            rows, next_cursor = self._pull_snmp_snapshot(target, prev.last_cursor)
        except Exception as exc:
            streak = prev.failure_streak + 1
            state = CollectorState(
                target_id=target.id,
                last_success_ts=prev.last_success_ts,
                last_run_ts=current_ts,
                last_error=f"snmp pull failed: {exc}",
                last_cursor=prev.last_cursor,
                failure_streak=streak,
            )
            severity = Severity.critical if streak >= 3 else Severity.warning
            return (
                [
                    Event(
                        asset_id=target.asset_id,
                        source="agentless_snmp",
                        message=f"[snmp] pull failed for '{target.name}': {exc}",
                        metric="collector_failure_streak",
                        value=float(streak),
                        severity=severity,
                    )
                ],
                state,
            )

        events: list[Event] = []
        for row in rows:
            events.append(
                Event(
                    asset_id=target.asset_id,
                    source="snmp_metric",
                    message=f"SNMP {row.get('oid')}={row.get('value')}",
                    metric=row.get("metric"),
                    value=row.get("value"),
                    severity=Severity.info,
                )
            )

        if not events:
            events.append(
                Event(
                    asset_id=target.asset_id,
                    source="agentless_snmp",
                    message=f"[snmp] no data for '{target.name}', cursor={next_cursor}",
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

    def _pull_ssh_snapshot(self, target: CollectorTarget, last_cursor: str | None) -> tuple[list[dict], str]:
        try:
            import paramiko  # type: ignore
        except ImportError as exc:
            raise RuntimeError("paramiko is not installed") from exc

        cursor = int(last_cursor) if (last_cursor and str(last_cursor).isdigit()) else 0
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=target.address,
                port=target.port,
                username=target.username,
                password=target.password,
                timeout=self.timeout_sec,
                look_for_keys=False,
                allow_agent=False,
            )

            rows: list[dict] = []
            metrics_cmd = target.ssh_metrics_command.strip() or "cat /proc/loadavg"
            _, stdout, _ = client.exec_command(metrics_cmd, timeout=self.timeout_sec)
            metrics_raw = stdout.read().decode("utf-8", errors="ignore").strip()
            if metrics_raw:
                first = metrics_raw.splitlines()[0]
                parts = first.split()
                if len(parts) >= 3:
                    for i, metric_name in enumerate(("load1", "load5", "load15")):
                        try:
                            rows.append(
                                {
                                    "kind": "metric",
                                    "metric": metric_name,
                                    "value": float(parts[i]),
                                    "message": f"SSH metric {metric_name}={parts[i]}",
                                }
                            )
                        except ValueError:
                            pass
                else:
                    rows.append({"kind": "log", "message": f"[ssh metrics] {first}"})

            tail_lines = max(1, min(target.ssh_tail_lines, 500))
            log_cmd = f"tail -n {tail_lines} {target.ssh_log_path}"
            _, stdout, _ = client.exec_command(log_cmd, timeout=self.timeout_sec)
            log_raw = stdout.read().decode("utf-8", errors="ignore")
            for line in [ln.strip() for ln in log_raw.splitlines() if ln.strip()]:
                rows.append({"kind": "log", "message": f"[ssh log] {line}"})

            next_cursor = str(max(cursor + 1, int(time.time())))
            return rows, next_cursor
        finally:
            client.close()

    def _pull_snmp_snapshot(self, target: CollectorTarget, last_cursor: str | None) -> tuple[list[dict], str]:
        try:
            from pysnmp.hlapi import (  # type: ignore
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                getCmd,
            )
        except ImportError as exc:
            raise RuntimeError("pysnmp is not installed") from exc

        oids = [o.strip() for o in target.snmp_oids.split(",") if o.strip()]
        if not oids:
            oids = ["1.3.6.1.2.1.1.3.0"]

        community = target.snmp_community or "public"
        snmp_mp = 1 if target.snmp_version == "2c" else 3
        rows: list[dict] = []
        for oid in oids:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=snmp_mp),
                UdpTransportTarget((target.address, target.port), timeout=self.timeout_sec, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
            error_indication, error_status, _, var_binds = next(iterator)
            if error_indication:
                raise RuntimeError(str(error_indication))
            if error_status:
                raise RuntimeError(str(error_status))

            for name, value in var_binds:
                metric_name = f"snmp_{str(name).replace('.', '_')}"
                try:
                    parsed_value: float | None = float(value)
                except Exception:
                    parsed_value = None
                rows.append({"oid": str(name), "metric": metric_name, "value": parsed_value})

        cursor = int(last_cursor) if (last_cursor and str(last_cursor).isdigit()) else 0
        next_cursor = str(max(cursor + 1, int(time.time())))
        return rows, next_cursor

    def _pull_winrm_records(self, target: CollectorTarget, last_cursor: str | None) -> tuple[list[dict], str]:
        try:
            import winrm  # type: ignore
        except ImportError as exc:
            raise RuntimeError("pywinrm is not installed") from exc

        cursor = int(last_cursor) if (last_cursor and str(last_cursor).isdigit()) else 0
        channels = [c.strip() for c in target.winrm_event_logs.split(",") if c.strip()]
        if not channels:
            channels = ["System", "Application"]
        channels_ps = ",".join("'" + c.replace("'", "''") + "'" for c in channels)
        batch_size = max(1, min(target.winrm_batch_size, 500))

        ps = f"""
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$last = {cursor}
$events = Get-WinEvent -FilterHashtable @{{LogName=@({channels_ps})}} -ErrorAction SilentlyContinue |
    Where-Object {{ $_.RecordId -gt $last }} |
    Sort-Object RecordId |
    Select-Object -First {batch_size} RecordId,Id,LogName,ProviderName,LevelDisplayName,TimeCreated,Message
$events | ConvertTo-Json -Depth 4 -Compress
"""
        scheme = "https" if target.winrm_use_https else "http"
        endpoint = f"{scheme}://{target.address}:{target.port}/wsman"
        transport = target.winrm_transport.strip().lower() or "ntlm"
        session = winrm.Session(
            endpoint,
            auth=(target.username, target.password),
            transport=transport,
            server_cert_validation="validate" if target.winrm_validate_tls else "ignore",
        )
        try:
            result = session.run_ps(ps)
        except UnicodeEncodeError as exc:
            raise RuntimeError(
                "WinRM auth transport cannot encode non-Latin credentials; use NTLM/Kerberos "
                "or Latin-1 credentials."
            ) from exc
        except Exception as exc:
            message = str(exc)
            exc_name = exc.__class__.__name__
            if (
                exc_name in {"ConnectTimeout", "ReadTimeout"}
                or "ConnectTimeoutError" in message
                or "timed out" in message.lower()
            ):
                raise RuntimeError(
                    f"WinRM endpoint timeout: {target.address}:{target.port} is unreachable or slow."
                ) from exc
            raise
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
