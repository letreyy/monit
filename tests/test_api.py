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
    assert "Swagger UI" in response.text


def test_overview_and_batch_flow() -> None:
    client.post(
        "/assets",
        json={"id": "srv-01", "name": "srv-01", "asset_type": "server", "location": "R1"},
    )

    ingest_resp = client.post(
        "/ingest/events",
        json={
            "events": [
                {
                    "asset_id": "srv-01",
                    "source": "linux",
                    "message": "thermal critical",
                    "severity": "critical",
                },
                {
                    "asset_id": "srv-01",
                    "source": "linux",
                    "message": "iowait spike",
                    "metric": "iowait",
                    "value": 30,
                    "severity": "warning",
                },
            ]
        },
    )
    assert ingest_resp.status_code == 200
    assert ingest_resp.json()["accepted"] == 2

    alerts_resp = client.get("/assets/srv-01/alerts")
    assert alerts_resp.status_code == 200
    assert len(alerts_resp.json()) >= 1

    overview_resp = client.get("/overview")
    assert overview_resp.status_code == 200
    assert overview_resp.json()["assets_total"] == 1
    assert overview_resp.json()["events_total"] == 2
