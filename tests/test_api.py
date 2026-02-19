from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main_module
from app.services import MonitoringService
from app.storage import SQLiteStorage


def setup_function() -> None:
    db_path = Path("data/test_monitor.db")
    if db_path.exists():
        db_path.unlink()
    main_module.service = MonitoringService(SQLiteStorage(str(db_path)))


client = TestClient(main_module.app)


def test_home_interface_page() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Dashboard" in response.text


def test_dashboard_and_windows_ingest_flow() -> None:
    client.post(
        "/assets",
        json={"id": "win-01", "name": "win-01", "asset_type": "server", "location": "R2"},
    )

    ingest_resp = client.post(
        "/ingest/events",
        json={
            "events": [
                {
                    "asset_id": "win-01",
                    "source": "windows_eventlog",
                    "message": "[System] EventID=6008 unexpected shutdown",
                    "severity": "critical",
                },
                {
                    "asset_id": "win-01",
                    "source": "windows_eventlog",
                    "message": "[Application] EventID=1000 app crash",
                    "severity": "warning",
                },
            ]
        },
    )
    assert ingest_resp.status_code == 200
    assert ingest_resp.json()["accepted"] == 2

    dashboard_resp = client.get("/dashboard")
    assert dashboard_resp.status_code == 200
    assert "InfraMind Dashboard" in dashboard_resp.text
    assert "win-01" in dashboard_resp.text

    overview_resp = client.get("/overview")
    assert overview_resp.status_code == 200
    assert overview_resp.json()["assets_total"] == 1
    assert overview_resp.json()["events_total"] == 2
