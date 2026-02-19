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


def test_ui_asset_event_detail_and_delete_flow() -> None:
    create_asset = client.post(
        "/ui/assets",
        data={"asset_id": "srv-ui-01", "name": "srv-ui-01", "asset_type": "server", "location": "R5"},
        follow_redirects=False,
    )
    assert create_asset.status_code == 303

    add_event = client.post(
        "/ui/events",
        data={
            "asset_id": "srv-ui-01",
            "source": "manual_ui",
            "message": "EventID=6008 unexpected shutdown",
            "severity": "critical",
        },
        follow_redirects=False,
    )
    assert add_event.status_code == 303

    detail_page = client.get("/ui/assets/srv-ui-01")
    assert detail_page.status_code == 200
    assert "Asset detail: srv-ui-01" in detail_page.text

    delete_asset = client.post("/ui/assets/srv-ui-01/delete", follow_redirects=False)
    assert delete_asset.status_code == 303

    assets_page = client.get("/ui/assets")
    assert "srv-ui-01" not in assets_page.text


def test_windows_correlation_endpoint() -> None:
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

    insights_resp = client.get("/assets/win-01/insights")
    assert insights_resp.status_code == 200
    assert len(insights_resp.json()) >= 2
