from __future__ import annotations

import sqlite3
from pathlib import Path

from app.models import Asset, Event


class SQLiteStorage:
    def __init__(self, db_path: str = "data/monitor.db") -> None:
        self.db_path = db_path
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
                    FOREIGN KEY(asset_id) REFERENCES assets(id)
                )
                """
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
            conn.execute("DELETE FROM events WHERE asset_id = ?", (asset_id,))
            conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))

    def list_assets(self) -> list[Asset]:
        with self._connect() as conn:
            rows = conn.execute("SELECT id, name, asset_type, location FROM assets ORDER BY id").fetchall()
        return [Asset(**dict(row)) for row in rows]

    def asset_exists(self, asset_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM assets WHERE id = ?", (asset_id,)).fetchone()
        return row is not None

    def insert_event(self, event: Event) -> Event:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO events(asset_id, source, message, metric, value, severity, timestamp)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.asset_id,
                    event.source,
                    event.message,
                    event.metric,
                    event.value,
                    event.severity.value,
                    event.timestamp.isoformat(),
                ),
            )
        return event

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
