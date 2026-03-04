from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime

from app.csb_merp import line_to_event
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


    @staticmethod
    def _parse_event_timestamp(raw: object) -> datetime | None:
        value = str(raw or "").strip()
        if not value:
            return None
        normalized = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized)
        except ValueError:
            return None


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
        if target.collector_type.value == "snmp":
            return self._collect_snmp_target(target)
        if target.collector_type.value == "ilo":
            return self._collect_ilo_target(target)
        return self._collect_csb_merp_share_target(target)

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
                    timestamp=self._parse_event_timestamp(row.get("TimeCreated")) or datetime.utcnow(),
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


    def _collect_ilo_target(self, target: CollectorTarget) -> tuple[list[Event], CollectorState]:
        prev = self.service.get_collector_state(target.id)
        current_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        try:
            rows, next_cursor = self._pull_ilo_redfish_events(target, prev.last_cursor)
        except Exception as exc:
            streak = prev.failure_streak + 1
            state = CollectorState(
                target_id=target.id,
                last_success_ts=prev.last_success_ts,
                last_run_ts=current_ts,
                last_error=f"ilo pull failed: {exc}",
                last_cursor=prev.last_cursor,
                failure_streak=streak,
            )
            severity = Severity.critical if streak >= 3 else Severity.warning
            return (
                [
                    Event(
                        asset_id=target.asset_id,
                        source="agentless_ilo",
                        message=f"[ilo] pull failed for '{target.name}': {exc}",
                        metric="collector_failure_streak",
                        value=float(streak),
                        severity=severity,
                    )
                ],
                state,
            )

        events: list[Event] = []
        for row in rows:
            sev_raw = str(row.get("Severity", "")).lower()
            severity = Severity.info
            if "warn" in sev_raw or "caution" in sev_raw:
                severity = Severity.warning
            if "crit" in sev_raw or "fatal" in sev_raw:
                severity = Severity.critical
            entry_id = row.get("Id") or row.get("EntryCode") or "unknown"
            created = row.get("Created") or row.get("CreatedTime") or ""
            message = row.get("Message") or row.get("Name") or "iLO log entry"
            events.append(
                Event(
                    asset_id=target.asset_id,
                    source="ilo_iml",
                    message=f"[iLO] Entry={entry_id} Created={created} Severity={row.get('Severity', 'Unknown')} :: {message}",
                    severity=severity,
                    timestamp=self._parse_event_timestamp(created) or datetime.utcnow(),
                )
            )

        if not events:
            events.append(
                Event(
                    asset_id=target.asset_id,
                    source="agentless_ilo",
                    message=f"[ilo] no new IML entries for '{target.name}', cursor={next_cursor}",
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

    def _collect_csb_merp_share_target(self, target: CollectorTarget) -> tuple[list[Event], CollectorState]:
        prev = self.service.get_collector_state(target.id)
        current_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        try:
            events, next_cursor = self._pull_csb_merp_share(target, prev.last_cursor)
        except Exception as exc:
            streak = prev.failure_streak + 1
            state = CollectorState(
                target_id=target.id,
                last_success_ts=prev.last_success_ts,
                last_run_ts=current_ts,
                last_error=f"csb share pull failed: {exc}",
                last_cursor=prev.last_cursor,
                failure_streak=streak,
            )
            severity = Severity.critical if streak >= 3 else Severity.warning
            return (
                [
                    Event(
                        asset_id=target.asset_id,
                        source="agentless_csb_merp",
                        message=f"[csb] pull failed for '{target.name}': {exc}",
                        metric="collector_failure_streak",
                        value=float(streak),
                        severity=severity,
                    )
                ],
                state,
            )

        if not events:
            events.append(
                Event(
                    asset_id=target.asset_id,
                    source="agentless_csb_merp",
                    message=f"[csb] no new records for '{target.name}', cursor updated",
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

    def _is_unc_share_path(self, value: str) -> bool:
        v = (value or "").strip()
        return v.startswith("//") or v.startswith("\\")

    def _load_csb_cursor(self, last_cursor: str | None) -> dict[str, dict[str, int]]:
        if not last_cursor:
            return {}
        try:
            raw = json.loads(last_cursor)
            if isinstance(raw, dict) and isinstance(raw.get("files"), dict):
                return {k: v for k, v in raw["files"].items() if isinstance(v, dict)}
        except Exception:
            return {}
        return {}

    def _pull_csb_merp_share(self, target: CollectorTarget, last_cursor: str | None) -> tuple[list[Event], str]:
        if self._is_unc_share_path(target.csb_share_path):
            return self._pull_csb_merp_share_unc(target, last_cursor)
        return self._pull_csb_merp_share_local(target, last_cursor)

    def _pull_csb_merp_share_local(self, target: CollectorTarget, last_cursor: str | None) -> tuple[list[Event], str]:
        path = Path(target.csb_share_path or "")
        if not path.exists() or not path.is_dir():
            raise RuntimeError(f"share path not found: {target.csb_share_path}")

        cursor_data = self._load_csb_cursor(last_cursor)
        files = sorted([p for p in path.rglob(target.csb_glob_pattern or "*.txt") if p.is_file()]) if target.csb_recursive else sorted([p for p in path.glob(target.csb_glob_pattern or "*.txt") if p.is_file()])
        files = files[: max(1, target.csb_max_files)]

        events: list[Event] = []
        new_cursor: dict[str, dict[str, int]] = {}

        for fp in files:
            key = str(fp)
            st = fp.stat()
            prev = cursor_data.get(key, {})
            prev_offset = int(prev.get("offset", 0))
            prev_inode = int(prev.get("inode", -1))
            inode = int(getattr(st, "st_ino", 0))
            size = int(st.st_size)

            offset = prev_offset
            if (prev_inode != -1 and prev_inode != inode) or size < prev_offset:
                offset = 0

            with fp.open("rb") as fh:
                fh.seek(max(0, offset))
                chunk = fh.read()
                next_offset = int(fh.tell())

            if chunk:
                for line in chunk.decode("utf-8", errors="ignore").splitlines():
                    if not line.strip():
                        continue
                    event = line_to_event(target.asset_id, line, source=target.csb_source or "csb_merp_txt")
                    if event is not None:
                        events.append(event)

            new_cursor[key] = {"offset": next_offset, "inode": inode, "size": size}

        return events, json.dumps({"files": new_cursor}, separators=(",", ":"))

    def _pull_csb_merp_share_unc(self, target: CollectorTarget, last_cursor: str | None) -> tuple[list[Event], str]:
        try:
            import smbclient  # type: ignore
        except ImportError as exc:
            raise RuntimeError("smbclient/smbprotocol is not installed") from exc

        share_path = target.csb_share_path.strip().replace("/", "\\")
        if not share_path.startswith("\\"):
            share_path = "\\" + share_path.lstrip("\\")

        parts = [p for p in share_path.split("\\") if p]
        if len(parts) < 2:
            raise RuntimeError(f"invalid UNC path: {target.csb_share_path}")
        server = parts[0]

        try:
            smbclient.register_session(server, username=target.username or None, password=target.password or None)
        except Exception as exc:
            raise RuntimeError(f"SMB auth/session failed: {exc}") from exc

        cursor_data = self._load_csb_cursor(last_cursor)

        files: list[str] = []
        pattern = target.csb_glob_pattern or "*.txt"
        try:
            import fnmatch
            if target.csb_recursive:
                for root, _dirs, filenames in smbclient.walk(share_path):
                    for name in filenames:
                        if fnmatch.fnmatch(name, pattern):
                            files.append(root.rstrip("\\") + "\\" + name)
            else:
                for entry in smbclient.scandir(share_path):
                    if entry.is_file() and fnmatch.fnmatch(entry.name, pattern):
                        files.append(share_path.rstrip("\\") + "\\" + entry.name)
        except Exception as exc:
            raise RuntimeError(f"SMB list failed: {exc}") from exc

        files = sorted(files)[: max(1, target.csb_max_files)]
        events: list[Event] = []
        new_cursor: dict[str, dict[str, int]] = {}

        for file_path in files:
            try:
                st = smbclient.stat(file_path)
            except Exception as exc:
                raise RuntimeError(f"SMB stat failed for {file_path}: {exc}") from exc

            prev = cursor_data.get(file_path, {})
            prev_offset = int(prev.get("offset", 0))
            size = int(getattr(st, "st_size", 0))
            offset = 0 if size < prev_offset else prev_offset

            try:
                with smbclient.open_file(file_path, mode="rb") as fh:
                    fh.seek(max(0, offset))
                    chunk = fh.read()
                    next_offset = int(fh.tell())
            except Exception as exc:
                raise RuntimeError(f"SMB read failed for {file_path}: {exc}") from exc

            if chunk:
                for line in chunk.decode("utf-8", errors="ignore").splitlines():
                    if not line.strip():
                        continue
                    event = line_to_event(target.asset_id, line, source=target.csb_source or "csb_merp_txt")
                    if event is not None:
                        events.append(event)

            new_cursor[file_path] = {"offset": next_offset, "size": size}

        return events, json.dumps({"files": new_cursor}, separators=(",", ":"))

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


    def _pull_ilo_redfish_events(self, target: CollectorTarget, last_cursor: str | None) -> tuple[list[dict], str]:
        import httpx

        scheme = "https" if target.ilo_use_https else "http"
        path = target.ilo_log_path.strip() or "/redfish/v1/Systems/1/LogServices/IML/Entries"
        if not path.startswith("/"):
            path = "/" + path

        request_limit = max(1, min(target.ilo_event_limit, 500))
        is_initial_pull = not (last_cursor and str(last_cursor).strip())
        if is_initial_pull:
            request_limit = max(request_limit, 100)

        def _full_url(relative_path: str) -> str:
            return f"{scheme}://{target.address}:{target.port}{relative_path}"

        def _discover_entries_path(client: object) -> str | None:
            try:
                systems_resp = client.get(_full_url("/redfish/v1/Systems"))
                systems_payload = systems_resp.json() if systems_resp.status_code < 400 else {}
            except Exception:
                return None
            members = systems_payload.get("Members") if isinstance(systems_payload, dict) else None
            if not isinstance(members, list):
                return None
            for system in members:
                system_path = ""
                if isinstance(system, dict):
                    system_path = str(system.get("@odata.id") or "").strip()
                if not system_path.startswith("/"):
                    continue
                logservices_path = f"{system_path.rstrip('/')}/LogServices"
                try:
                    ls_resp = client.get(_full_url(logservices_path))
                    ls_payload = ls_resp.json() if ls_resp.status_code < 400 else {}
                except Exception:
                    continue
                ls_members = ls_payload.get("Members") if isinstance(ls_payload, dict) else None
                if not isinstance(ls_members, list):
                    continue
                for service in ls_members:
                    service_path = ""
                    if isinstance(service, dict):
                        service_path = str(service.get("@odata.id") or "").strip()
                    if not service_path.startswith("/"):
                        continue
                    try:
                        svc_resp = client.get(_full_url(service_path))
                        svc_payload = svc_resp.json() if svc_resp.status_code < 400 else {}
                    except Exception:
                        svc_payload = {}
                    entries_path = ""
                    if isinstance(svc_payload, dict):
                        entries = svc_payload.get("Entries")
                        if isinstance(entries, dict):
                            entries_path = str(entries.get("@odata.id") or "").strip()
                    if not entries_path.startswith("/"):
                        entries_path = f"{service_path.rstrip('/')}/Entries"
                    try:
                        probe = client.get(_full_url(entries_path), params={"$top": 1})
                        if probe.status_code < 400:
                            return entries_path
                    except Exception:
                        continue
            return None

        endpoint = _full_url(path)
        try:
            with httpx.Client(
                timeout=self.timeout_sec,
                verify=target.ilo_validate_tls,
                auth=httpx.BasicAuth(target.username, target.password),
            ) as client:
                response = client.get(endpoint, params={"$top": request_limit})
                if response.status_code == 404:
                    discovered_path = _discover_entries_path(client)
                    if discovered_path and discovered_path != path:
                        endpoint = _full_url(discovered_path)
                        response = client.get(endpoint, params={"$top": request_limit})
        except Exception as exc:
            message = str(exc)
            name = exc.__class__.__name__
            if (
                name in {"ConnectError", "ConnectTimeout", "ReadTimeout"}
                or "Connection refused" in message
                or "Errno 111" in message
                or "timed out" in message.lower()
            ):
                raise RuntimeError(
                    f"iLO endpoint connection failed: {target.address}:{target.port} ({scheme.upper()}). "
                    "Check reachability, port and protocol (typical iLO is HTTPS/443)."
                ) from exc
            raise

        if response.status_code >= 400:
            raise RuntimeError(f"Redfish HTTP {response.status_code}: {response.text[:200].strip()}")

        raw_text = getattr(response, "text", None)
        raw_body = str(raw_text or "").strip() if raw_text is not None else None
        if response.status_code == 204 or (raw_body is not None and not raw_body):
            cursor = int(last_cursor) if (last_cursor and str(last_cursor).isdigit()) else 0
            return [], str(cursor)

        try:
            payload = response.json()
        except Exception as exc:
            body_preview = (response.text or "").strip().replace("\n", " ")[:200]
            ctype = response.headers.get("content-type", "") if getattr(response, "headers", None) else ""
            raise RuntimeError(
                "Redfish response is not valid JSON "
                f"(content-type='{ctype or 'unknown'}', body='{body_preview or '<empty>'}'). "
                "Check iLO credentials/auth method and Redfish log path."
            ) from exc

        if not isinstance(payload, dict):
            raise RuntimeError(
                f"Redfish response must be a JSON object, got {type(payload).__name__}. "
                "Check iLO log path."
            )

        members = payload.get("Members") if isinstance(payload, dict) else None
        rows = members if isinstance(members, list) else []

        cursor = int(last_cursor) if (last_cursor and str(last_cursor).isdigit()) else 0
        filtered: list[dict] = []
        max_cursor = cursor
        for row in rows:
            raw_id = row.get("Id")
            row_id = None
            try:
                row_id = int(str(raw_id))
            except Exception:
                pass
            if row_id is None or row_id > cursor:
                filtered.append(row)
            if row_id is not None:
                max_cursor = max(max_cursor, row_id)

        return filtered, str(max_cursor)

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
