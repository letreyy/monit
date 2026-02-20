from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main_module
from app.services import MonitoringService
from app.storage import SQLiteStorage
from app.worker import AgentlessWorker


def setup_function() -> None:
    db_path = Path("data/test_monitor.db")
    if db_path.exists():
        db_path.unlink()
    main_module.service = MonitoringService(SQLiteStorage(str(db_path)))
    main_module.worker = AgentlessWorker(main_module.service)


client = TestClient(main_module.app)


def test_ui_collector_target_flow() -> None:
    client.post(
        "/ui/assets",
        data={"asset_id": "srv-01", "name": "srv-01", "asset_type": "server", "location": "R1"},
    )

    resp = client.post(
        "/ui/collectors",
        data={
            "target_id": "col-01",
            "name": "Windows collector",
            "collector_type": "winrm",
            "address": "10.10.10.5",
            "port": "5985",
            "username": "admin",
            "password": "secret",
            "asset_id": "srv-01",
            "poll_interval_sec": "60",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303

    ui_page = client.get("/ui/collectors")
    assert ui_page.status_code == 200
    assert "col-01" in ui_page.text

    api_page = client.get("/collectors")
    assert api_page.status_code == 200
    assert api_page.json()[0]["collector_type"] == "winrm"


def test_windows_correlation_endpoint() -> None:
    client.post(
        "/assets",
        json={"id": "win-01", "name": "win-01", "asset_type": "server", "location": "R2"},
    )

    ingest_resp = client.post(
        "/ingest/events",
        json={
            "events": [
                {"asset_id": "win-01", "source": "windows_eventlog", "message": "EventID=6008", "severity": "critical"},
                {"asset_id": "win-01", "source": "windows_eventlog", "message": "EventID=41", "severity": "critical"},
                {"asset_id": "win-01", "source": "windows_eventlog", "message": "EventID=4625", "severity": "warning"},
                {"asset_id": "win-01", "source": "windows_eventlog", "message": "EventID=4625", "severity": "warning"},
                {"asset_id": "win-01", "source": "windows_eventlog", "message": "EventID=4625", "severity": "warning"},
                {"asset_id": "win-01", "source": "windows_eventlog", "message": "EventID=4625", "severity": "warning"},
                {"asset_id": "win-01", "source": "windows_eventlog", "message": "EventID=4625", "severity": "warning"},
            ]
        },
    )
    assert ingest_resp.status_code == 200

    insights_resp = client.get("/assets/win-01/insights")
    assert insights_resp.status_code == 200
    assert len(insights_resp.json()) >= 2


def test_worker_run_once_generates_agentless_event() -> None:
    client.post(
        "/assets",
        json={"id": "srv-worker", "name": "srv-worker", "asset_type": "server", "location": "R3"},
    )
    client.post(
        "/collectors",
        json={
            "id": "col-worker",
            "name": "Worker target",
            "address": "127.0.0.1",
            "collector_type": "ssh",
            "port": 1,
            "username": "u",
            "password": "p",
            "poll_interval_sec": 10,
            "enabled": True,
            "asset_id": "srv-worker"
        },
    )

    run_resp = client.post("/worker/run-once")
    assert run_resp.status_code == 200
    assert run_resp.json()["accepted"] >= 1

    events_resp = client.get("/assets/srv-worker/events")
    assert events_resp.status_code == 200
    assert any(e["source"].startswith("agentless_") for e in events_resp.json())
