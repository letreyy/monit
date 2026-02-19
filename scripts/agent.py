#!/usr/bin/env python3
"""Simple host agent that pushes metrics/log samples to InfraMind API.

Usage:
  python scripts/agent.py --api http://127.0.0.1:8000 --asset-id srv-01 --interval 30
"""

from __future__ import annotations

import argparse
import json
import shutil
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def post_json(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        body = response.read().decode("utf-8")
        return json.loads(body) if body else {}


def collect_metrics(asset_id: str) -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    load1 = float(Path("/proc/loadavg").read_text(encoding="utf-8").split()[0])
    disk = shutil.disk_usage("/")
    disk_used_pct = round((disk.used / disk.total) * 100, 2)

    return [
        {
            "asset_id": asset_id,
            "source": "agent",
            "message": "host load sample",
            "metric": "load1",
            "value": load1,
            "severity": "info",
            "timestamp": now,
        },
        {
            "asset_id": asset_id,
            "source": "agent",
            "message": "root fs usage",
            "metric": "disk_used_pct",
            "value": disk_used_pct,
            "severity": "warning" if disk_used_pct >= 85 else "info",
            "timestamp": now,
        },
    ]


def collect_log_events(asset_id: str, logfile: str) -> list[dict]:
    path = Path(logfile)
    if not path.exists():
        return []

    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[-20:]
    events: list[dict] = []
    now = datetime.now(timezone.utc).isoformat()

    for line in lines:
        lowered = line.lower()
        severity = "info"
        if "error" in lowered or "failed" in lowered:
            severity = "warning"
        if "panic" in lowered or "critical" in lowered:
            severity = "critical"

        events.append(
            {
                "asset_id": asset_id,
                "source": "logfile",
                "message": line[:500],
                "severity": severity,
                "timestamp": now,
            }
        )

    return events


def ensure_asset(api: str, asset_id: str, location: str) -> None:
    payload = {
        "id": asset_id,
        "name": asset_id,
        "asset_type": "server",
        "location": location,
    }
    post_json(f"{api}/assets", payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--asset-id", required=True)
    parser.add_argument("--location", default="unknown")
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--logfile", default="/var/log/syslog")
    args = parser.parse_args()

    ensure_asset(args.api, args.asset_id, args.location)

    while True:
        events = collect_metrics(args.asset_id) + collect_log_events(args.asset_id, args.logfile)
        payload = {"events": events}
        post_json(f"{args.api}/ingest/events", payload)
        print(f"[{datetime.now().isoformat()}] sent {len(events)} events")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
