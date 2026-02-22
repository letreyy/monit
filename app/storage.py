from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.models import AccessAuditEntry, Asset, CollectorState, CollectorTarget, Event, LogAnalyticsPolicy, LogAnalyticsPolicyAuditEntry, WorkerHistoryEntry
from app.security import SecretCodec, build_secret_codec


class SQLiteStorage:
    def __init__(self, db_path: str = "data/monitor.db", secret_codec: SecretCodec | None = None) -> None:
        self.db_path = db_path
        self.secret_codec = secret_codec or build_secret_codec()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    location TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    message TEXT NOT NULL,
                    metric TEXT,
                    value REAL,
                    severity TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    fingerprint TEXT,
                    FOREIGN KEY(asset_id) REFERENCES assets(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS collector_targets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    address TEXT NOT NULL,
                    collector_type TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    poll_interval_sec INTEGER NOT NULL,
                    enabled INTEGER NOT NULL,
                    asset_id TEXT NOT NULL,
                    winrm_transport TEXT NOT NULL DEFAULT 'ntlm',
                    winrm_use_https INTEGER NOT NULL DEFAULT 0,
                    winrm_validate_tls INTEGER NOT NULL DEFAULT 0,
                    winrm_event_logs TEXT NOT NULL DEFAULT 'System,Application',
                    winrm_batch_size INTEGER NOT NULL DEFAULT 50,
                    ssh_metrics_command TEXT NOT NULL DEFAULT 'cat /proc/loadavg',
                    ssh_log_path TEXT NOT NULL DEFAULT '/var/log/syslog',
                    ssh_tail_lines INTEGER NOT NULL DEFAULT 50,
                    snmp_community TEXT NOT NULL DEFAULT 'public',
                    snmp_version TEXT NOT NULL DEFAULT '2c',
                    snmp_oids TEXT NOT NULL DEFAULT '1.3.6.1.2.1.1.3.0,1.3.6.1.2.1.1.5.0',
                    FOREIGN KEY(asset_id) REFERENCES assets(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS collector_state (
                    target_id TEXT PRIMARY KEY,
                    last_success_ts TEXT,
                    last_run_ts TEXT,
                    last_error TEXT,
                    last_cursor TEXT,
                    failure_streak INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(target_id) REFERENCES collector_targets(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS worker_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    collector_type TEXT NOT NULL,
                    accepted_events INTEGER NOT NULL,
                    last_error TEXT,
                    failure_streak INTEGER NOT NULL,
                    last_cursor TEXT,
                    FOREIGN KEY(target_id) REFERENCES collector_targets(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ai_log_policies (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    tenant_id TEXT,
                    ignore_sources TEXT NOT NULL DEFAULT '',
                    ignore_signatures TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ai_log_policy_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    policy_id TEXT NOT NULL,
                    tenant_id TEXT,
                    action TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    details TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS access_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL
                )
                """
            )
            self._ensure_events_columns(conn)
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_worker_history_ts ON worker_history(ts)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_access_audit_ts ON access_audit(ts)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_ai_log_policies_enabled ON ai_log_policies(enabled)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_ai_log_policy_audit_ts ON ai_log_policy_audit(ts)
                """
            )
            self._ensure_collector_target_columns(conn)
            self._ensure_ai_log_policy_columns(conn)

    def _ensure_events_columns(self, conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(events)").fetchall()}
        if "fingerprint" not in columns:
            conn.execute("ALTER TABLE events ADD COLUMN fingerprint TEXT")

    def _ensure_ai_log_policy_columns(self, conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(ai_log_policies)").fetchall()}
        if "tenant_id" not in columns:
            conn.execute("ALTER TABLE ai_log_policies ADD COLUMN tenant_id TEXT")

    def _ensure_collector_target_columns(self, conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(collector_targets)").fetchall()}
        if "winrm_transport" not in columns:
            conn.execute("ALTER TABLE collector_targets ADD COLUMN winrm_transport TEXT NOT NULL DEFAULT 'ntlm'")
        if "winrm_use_https" not in columns:
            conn.execute("ALTER TABLE collector_targets ADD COLUMN winrm_use_https INTEGER NOT NULL DEFAULT 0")
        if "winrm_validate_tls" not in columns:
            conn.execute("ALTER TABLE collector_targets ADD COLUMN winrm_validate_tls INTEGER NOT NULL DEFAULT 0")
        if "winrm_event_logs" not in columns:
            conn.execute(
                "ALTER TABLE collector_targets ADD COLUMN winrm_event_logs TEXT NOT NULL DEFAULT 'System,Application'"
            )
        if "winrm_batch_size" not in columns:
            conn.execute("ALTER TABLE collector_targets ADD COLUMN winrm_batch_size INTEGER NOT NULL DEFAULT 50")
        if "ssh_metrics_command" not in columns:
            conn.execute(
                "ALTER TABLE collector_targets ADD COLUMN ssh_metrics_command TEXT NOT NULL DEFAULT 'cat /proc/loadavg'"
            )
        if "ssh_log_path" not in columns:
            conn.execute("ALTER TABLE collector_targets ADD COLUMN ssh_log_path TEXT NOT NULL DEFAULT '/var/log/syslog'")
        if "ssh_tail_lines" not in columns:
            conn.execute("ALTER TABLE collector_targets ADD COLUMN ssh_tail_lines INTEGER NOT NULL DEFAULT 50")
        if "snmp_community" not in columns:
            conn.execute("ALTER TABLE collector_targets ADD COLUMN snmp_community TEXT NOT NULL DEFAULT 'public'")
        if "snmp_version" not in columns:
            conn.execute("ALTER TABLE collector_targets ADD COLUMN snmp_version TEXT NOT NULL DEFAULT '2c'")
        if "snmp_oids" not in columns:
            conn.execute(
                "ALTER TABLE collector_targets ADD COLUMN snmp_oids TEXT NOT NULL DEFAULT '1.3.6.1.2.1.1.3.0,1.3.6.1.2.1.1.5.0'"
            )

    def upsert_asset(self, asset: Asset) -> Asset:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO assets(id, name, asset_type, location)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    asset_type=excluded.asset_type,
                    location=excluded.location
                """,
                (asset.id, asset.name, asset.asset_type.value, asset.location),
            )
        return asset

    def delete_asset(self, asset_id: str) -> None:
        with self._connect() as conn:
            target_rows = conn.execute("SELECT id FROM collector_targets WHERE asset_id = ?", (asset_id,)).fetchall()
            for row in target_rows:
                conn.execute("DELETE FROM collector_state WHERE target_id = ?", (row["id"],))
            conn.execute("DELETE FROM events WHERE asset_id = ?", (asset_id,))
            conn.execute("DELETE FROM collector_targets WHERE asset_id = ?", (asset_id,))
            conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))

    def list_assets(self) -> list[Asset]:
        with self._connect() as conn:
            rows = conn.execute("SELECT id, name, asset_type, location FROM assets ORDER BY id").fetchall()
        return [Asset(**dict(row)) for row in rows]

    def asset_exists(self, asset_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM assets WHERE id = ?", (asset_id,)).fetchone()
        return row is not None

    def upsert_collector_target(self, target: CollectorTarget) -> CollectorTarget:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO collector_targets(
                    id, name, address, collector_type, port, username, password,
                    poll_interval_sec, enabled, asset_id,
                    winrm_transport, winrm_use_https, winrm_validate_tls, winrm_event_logs, winrm_batch_size,
                    ssh_metrics_command, ssh_log_path, ssh_tail_lines,
                    snmp_community, snmp_version, snmp_oids
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    address=excluded.address,
                    collector_type=excluded.collector_type,
                    port=excluded.port,
                    username=excluded.username,
                    password=excluded.password,
                    poll_interval_sec=excluded.poll_interval_sec,
                    enabled=excluded.enabled,
                    asset_id=excluded.asset_id,
                    winrm_transport=excluded.winrm_transport,
                    winrm_use_https=excluded.winrm_use_https,
                    winrm_validate_tls=excluded.winrm_validate_tls,
                    winrm_event_logs=excluded.winrm_event_logs,
                    winrm_batch_size=excluded.winrm_batch_size,
                    ssh_metrics_command=excluded.ssh_metrics_command,
                    ssh_log_path=excluded.ssh_log_path,
                    ssh_tail_lines=excluded.ssh_tail_lines,
                    snmp_community=excluded.snmp_community,
                    snmp_version=excluded.snmp_version,
                    snmp_oids=excluded.snmp_oids
                """,
                (
                    target.id,
                    target.name,
                    target.address,
                    target.collector_type.value,
                    target.port,
                    target.username,
                    self.secret_codec.encrypt(target.password),
                    target.poll_interval_sec,
                    1 if target.enabled else 0,
                    target.asset_id,
                    target.winrm_transport,
                    1 if target.winrm_use_https else 0,
                    1 if target.winrm_validate_tls else 0,
                    target.winrm_event_logs,
                    target.winrm_batch_size,
                    target.ssh_metrics_command,
                    target.ssh_log_path,
                    target.ssh_tail_lines,
                    self.secret_codec.encrypt(target.snmp_community),
                    target.snmp_version,
                    target.snmp_oids,
                ),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO collector_state(target_id, failure_streak)
                VALUES(?, 0)
                """,
                (target.id,),
            )
        return target

    def list_collector_targets(self) -> list[CollectorTarget]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, name, address, collector_type, port, username, password,
                       poll_interval_sec, enabled, asset_id,
                       winrm_transport, winrm_use_https, winrm_validate_tls, winrm_event_logs, winrm_batch_size,
                       ssh_metrics_command, ssh_log_path, ssh_tail_lines,
                       snmp_community, snmp_version, snmp_oids
                FROM collector_targets
                ORDER BY id
                """
            ).fetchall()

        result = []
        for row in rows:
            data = dict(row)
            data["enabled"] = bool(data["enabled"])
            data["winrm_use_https"] = bool(data["winrm_use_https"])
            data["winrm_validate_tls"] = bool(data["winrm_validate_tls"])
            data["password"] = self.secret_codec.decrypt(data["password"])
            data["snmp_community"] = self.secret_codec.decrypt(data["snmp_community"])
            result.append(CollectorTarget(**data))
        return result

    def delete_collector_target(self, target_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM collector_state WHERE target_id = ?", (target_id,))
            conn.execute("DELETE FROM collector_targets WHERE id = ?", (target_id,))

    def upsert_collector_state(self, state: CollectorState) -> CollectorState:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO collector_state(target_id, last_success_ts, last_run_ts, last_error, last_cursor, failure_streak)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_id) DO UPDATE SET
                    last_success_ts=excluded.last_success_ts,
                    last_run_ts=excluded.last_run_ts,
                    last_error=excluded.last_error,
                    last_cursor=excluded.last_cursor,
                    failure_streak=excluded.failure_streak
                """,
                (
                    state.target_id,
                    state.last_success_ts,
                    state.last_run_ts,
                    state.last_error,
                    state.last_cursor,
                    state.failure_streak,
                ),
            )
        return state

    def get_collector_state(self, target_id: str) -> CollectorState:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT target_id, last_success_ts, last_run_ts, last_error, last_cursor, failure_streak
                FROM collector_state
                WHERE target_id = ?
                """,
                (target_id,),
            ).fetchone()

        if row:
            return CollectorState(**dict(row))
        return CollectorState(target_id=target_id)


    def insert_worker_history(self, entry: WorkerHistoryEntry) -> WorkerHistoryEntry:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO worker_history(ts, target_id, collector_type, accepted_events, last_error, failure_streak, last_cursor)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.ts,
                    entry.target_id,
                    entry.collector_type,
                    entry.accepted_events,
                    entry.last_error,
                    entry.failure_streak,
                    entry.last_cursor,
                ),
            )
        return entry

    def list_worker_history(
        self,
        limit: int = 100,
        target_id: str | None = None,
        collector_type: str | None = None,
        has_error: bool | None = None,
    ) -> list[WorkerHistoryEntry]:
        where: list[str] = []
        params: list[object] = []
        if target_id:
            where.append("target_id = ?")
            params.append(target_id)
        if collector_type:
            where.append("collector_type = ?")
            params.append(collector_type)
        if has_error is True:
            where.append("last_error IS NOT NULL")
        elif has_error is False:
            where.append("last_error IS NULL")

        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        q = f"""
            SELECT ts, target_id, collector_type, accepted_events, last_error, failure_streak, last_cursor
            FROM worker_history
            {where_sql}
            ORDER BY id DESC
            LIMIT ?
        """
        params.append(max(1, min(limit, 1000)))

        with self._connect() as conn:
            rows = conn.execute(q, tuple(params)).fetchall()
        return [WorkerHistoryEntry(**dict(r)) for r in rows]



    def insert_access_audit(self, entry: AccessAuditEntry) -> AccessAuditEntry:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO access_audit(ts, path, role, action, result)
                VALUES(?, ?, ?, ?, ?)
                """,
                (entry.ts, entry.path, entry.role, entry.action, entry.result),
            )
            conn.execute(
                """
                DELETE FROM access_audit
                WHERE id NOT IN (
                    SELECT id FROM access_audit ORDER BY id DESC LIMIT 500
                )
                """
            )
        return entry

    def list_access_audit(self, limit: int = 100) -> list[AccessAuditEntry]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT ts, path, role, action, result
                FROM access_audit
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [AccessAuditEntry(**dict(r)) for r in rows]

    def delete_access_audit_older_than(self, min_ts: int) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM access_audit WHERE ts < ?", (int(min_ts),))
            return int(cur.rowcount or 0)

    def delete_worker_history_older_than(self, min_ts_iso: str) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM worker_history WHERE ts < ?", (min_ts_iso,))
            return int(cur.rowcount or 0)



    def delete_ai_log_policy_audit_older_than(self, min_ts: int) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM ai_log_policy_audit WHERE ts < ?", (int(min_ts),))
            return int(cur.rowcount or 0)

    def upsert_ai_log_policy(self, policy: LogAnalyticsPolicy) -> LogAnalyticsPolicy:
        ignore_sources = ",".join(policy.ignore_sources)
        ignore_signatures = ",".join(policy.ignore_signatures)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ai_log_policies(id, name, tenant_id, ignore_sources, ignore_signatures, enabled)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    tenant_id=excluded.tenant_id,
                    ignore_sources=excluded.ignore_sources,
                    ignore_signatures=excluded.ignore_signatures,
                    enabled=excluded.enabled
                """,
                (policy.id, policy.name, policy.tenant_id, ignore_sources, ignore_signatures, 1 if policy.enabled else 0),
            )
        return policy

    def list_ai_log_policies(self, enabled_only: bool = False, tenant_id: str | None = None) -> list[LogAnalyticsPolicy]:
        query = "SELECT id, name, tenant_id, ignore_sources, ignore_signatures, enabled FROM ai_log_policies"
        params: tuple[object, ...] = ()
        where_parts: list[str] = []
        if enabled_only:
            where_parts.append("enabled = 1")
        if tenant_id is not None:
            where_parts.append("tenant_id = ?")
            params = (tenant_id,)
        if where_parts:
            query += " WHERE " + " AND ".join(where_parts)
        query += " ORDER BY id"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        result: list[LogAnalyticsPolicy] = []
        for row in rows:
            ignore_sources = [item.strip().lower() for item in row["ignore_sources"].split(",") if item.strip()]
            ignore_signatures = [item.strip().lower() for item in row["ignore_signatures"].split(",") if item.strip()]
            result.append(
                LogAnalyticsPolicy(
                    id=row["id"],
                    name=row["name"],
                    tenant_id=row["tenant_id"],
                    ignore_sources=ignore_sources,
                    ignore_signatures=ignore_signatures,
                    enabled=bool(row["enabled"]),
                )
            )
        return result

    def get_ai_log_policy(self, policy_id: str, tenant_id: str | None = None) -> LogAnalyticsPolicy | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, name, tenant_id, ignore_sources, ignore_signatures, enabled FROM ai_log_policies WHERE id = ?",
                (policy_id,),
            ).fetchone()
        if row is None:
            return None
        if tenant_id is not None and row["tenant_id"] != tenant_id:
            return None
        ignore_sources = [item.strip().lower() for item in row["ignore_sources"].split(",") if item.strip()]
        ignore_signatures = [item.strip().lower() for item in row["ignore_signatures"].split(",") if item.strip()]
        return LogAnalyticsPolicy(
            id=row["id"],
            name=row["name"],
            tenant_id=row["tenant_id"],
            ignore_sources=ignore_sources,
            ignore_signatures=ignore_signatures,
            enabled=bool(row["enabled"]),
        )

    def delete_ai_log_policy(self, policy_id: str, tenant_id: str | None = None) -> int:
        with self._connect() as conn:
            if tenant_id is None:
                cur = conn.execute("DELETE FROM ai_log_policies WHERE id = ?", (policy_id,))
            else:
                cur = conn.execute("DELETE FROM ai_log_policies WHERE id = ? AND tenant_id = ?", (policy_id, tenant_id))
            return int(cur.rowcount or 0)


    def insert_ai_log_policy_audit(self, entry: LogAnalyticsPolicyAuditEntry) -> LogAnalyticsPolicyAuditEntry:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ai_log_policy_audit(ts, policy_id, tenant_id, action, actor_role, details)
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (entry.ts, entry.policy_id, entry.tenant_id, entry.action, entry.actor_role, entry.details),
            )
        return entry


    def count_ai_log_policy_audit(
        self,
        tenant_id: str | None = None,
        action: str | None = None,
        policy_id: str | None = None,
        min_ts: int | None = None,
        max_ts: int | None = None,
    ) -> int:
        query = "SELECT COUNT(1) AS c FROM ai_log_policy_audit"
        where_parts: list[str] = []
        params: list[object] = []

        if tenant_id is not None:
            where_parts.append("tenant_id = ?")
            params.append(tenant_id)
        if action is not None:
            where_parts.append("action = ?")
            params.append(action)
        if policy_id is not None:
            where_parts.append("policy_id = ?")
            params.append(policy_id)
        if min_ts is not None:
            where_parts.append("ts >= ?")
            params.append(int(min_ts))
        if max_ts is not None:
            where_parts.append("ts <= ?")
            params.append(int(max_ts))

        if where_parts:
            query += " WHERE " + " AND ".join(where_parts)

        with self._connect() as conn:
            row = conn.execute(query, tuple(params)).fetchone()
        return int(row["c"] if row else 0)

    def list_ai_log_policy_audit(
        self,
        limit: int = 100,
        tenant_id: str | None = None,
        action: str | None = None,
        policy_id: str | None = None,
        min_ts: int | None = None,
        max_ts: int | None = None,
        sort: str = "desc",
        offset: int = 0,
    ) -> list[LogAnalyticsPolicyAuditEntry]:
        query = "SELECT ts, policy_id, tenant_id, action, actor_role, details FROM ai_log_policy_audit"
        where_parts: list[str] = []
        params: list[object] = []

        if tenant_id is not None:
            where_parts.append("tenant_id = ?")
            params.append(tenant_id)
        if action is not None:
            where_parts.append("action = ?")
            params.append(action)
        if policy_id is not None:
            where_parts.append("policy_id = ?")
            params.append(policy_id)
        if min_ts is not None:
            where_parts.append("ts >= ?")
            params.append(int(min_ts))
        if max_ts is not None:
            where_parts.append("ts <= ?")
            params.append(int(max_ts))

        if where_parts:
            query += " WHERE " + " AND ".join(where_parts)
        direction = "ASC" if str(sort).lower() == "asc" else "DESC"
        query += f" ORDER BY id {direction} LIMIT ? OFFSET ?"
        params.append(max(1, min(limit, 1000)))
        params.append(max(0, offset))

        with self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [LogAnalyticsPolicyAuditEntry(**dict(row)) for row in rows]

    @staticmethod
    def _fingerprint(event: Event) -> str:
        basis = "|".join(
            [
                event.asset_id,
                event.source,
                event.message,
                event.metric or "",
                str(event.value) if event.value is not None else "",
                event.severity.value,
            ]
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()

    def insert_event(self, event: Event, dedup_window_sec: int = 300) -> tuple[Event, bool]:
        fingerprint = self._fingerprint(event)

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT timestamp FROM events
                WHERE fingerprint = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (fingerprint,),
            ).fetchone()

            if row:
                try:
                    last_ts = datetime.fromisoformat(row["timestamp"])
                    if last_ts.tzinfo is None:
                        last_ts = last_ts.replace(tzinfo=timezone.utc)
                    cur_ts = event.timestamp
                    if cur_ts.tzinfo is None:
                        cur_ts = cur_ts.replace(tzinfo=timezone.utc)
                    age_sec = (cur_ts - last_ts).total_seconds()
                    if age_sec <= dedup_window_sec:
                        return event, False
                except Exception:
                    return event, False

            conn.execute(
                """
                INSERT INTO events(asset_id, source, message, metric, value, severity, timestamp, fingerprint)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.asset_id,
                    event.source,
                    event.message,
                    event.metric,
                    event.value,
                    event.severity.value,
                    event.timestamp.isoformat(),
                    fingerprint,
                ),
            )
        return event, True

    def list_events(self, asset_id: str, limit: int = 1000) -> list[Event]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT asset_id, source, message, metric, value, severity, timestamp
                FROM events
                WHERE asset_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (asset_id, limit),
            ).fetchall()

        return [Event(**dict(row)) for row in rows]
