from fastapi.testclient import TestClient

from app.main import app, service


client = TestClient(app)


def setup_function() -> None:
    service.assets.clear()
    service.events.clear()


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_register_event_requires_existing_asset() -> None:
    response = client.post(
        "/events",
        json={
            "asset_id": "srv-01",
            "source": "linux",
            "message": "disk issue",
            "severity": "warning",
        },
    )
    assert response.status_code == 404


def test_recommendation_flow() -> None:
    asset_payload = {
        "id": "srv-db-03",
        "name": "DB node",
        "asset_type": "server",
        "location": "R3",
    }
    response = client.post("/assets", json=asset_payload)
    assert response.status_code == 200

    events = [
        {
            "asset_id": "srv-db-03",
            "source": "linux",
            "message": "iowait spike",
            "metric": "iowait",
            "value": 29,
            "severity": "warning",
        },
        {
            "asset_id": "srv-db-03",
            "source": "idrac",
            "message": "thermal warning on inlet",
            "severity": "critical",
        },
        {
            "asset_id": "srv-db-03",
            "source": "smart",
            "message": "SMART reallocated sector count increased",
            "severity": "critical",
        },
    ]

    for event in events:
        event_resp = client.post("/events", json=event)
        assert event_resp.status_code == 200

    rec_resp = client.get("/assets/srv-db-03/recommendation")
    assert rec_resp.status_code == 200

    payload = rec_resp.json()
    assert payload["risk_score"] >= 0.75
    assert len(payload["actions"]) >= 2
