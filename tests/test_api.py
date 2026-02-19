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
    assert "insights" in response.text.lower()


def test_dashboard_and_windows_correlation_flow() -> None:
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
                    "message": "[System] EventID=41 kernel power",
                    "severity": "critical",
                },
                {
                    "asset_id": "win-01",
                    "source": "windows_eventlog",
                    "message": "[Security] EventID=4625 failed logon",
                    "severity": "warning",
                },
                {
                    "asset_id": "win-01",
                    "source": "windows_eventlog",
                    "message": "[Security] EventID=4625 failed logon",
                    "severity": "warning",
                },
                {
                    "asset_id": "win-01",
                    "source": "windows_eventlog",
                    "message": "[Security] EventID=4625 failed logon",
                    "severity": "warning",
                },
                {
                    "asset_id": "win-01",
                    "source": "windows_eventlog",
                    "message": "[Security] EventID=4625 failed logon",
                    "severity": "warning",
                },
                {
                    "asset_id": "win-01",
                    "source": "windows_eventlog",
                    "message": "[Security] EventID=4625 failed logon",
                    "severity": "warning",
                },
            ]
        },
    )
    assert ingest_resp.status_code == 200
    assert ingest_resp.json()["accepted"] == 7

    insights_resp = client.get("/assets/win-01/insights")
    assert insights_resp.status_code == 200
    insights_payload = insights_resp.json()
    assert len(insights_payload) >= 2

    rec_resp = client.get("/assets/win-01/recommendation")
    assert rec_resp.status_code == 200
    actions = rec_resp.json()["actions"]
    assert any("Correlation:" in action for action in actions)

    dashboard_resp = client.get("/dashboard")
    assert dashboard_resp.status_code == 200
    assert "Insights" in dashboard_resp.text
