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
            "winrm_transport": "basic",
            "winrm_event_logs": "System,Application,Security",
            "winrm_batch_size": "25",
            "winrm_use_https": "on",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303

    api_page = client.get("/collectors")
    assert api_page.status_code == 200
    assert api_page.json()[0]["collector_type"] == "winrm"
    assert api_page.json()[0]["winrm_transport"] == "basic"
    assert api_page.json()[0]["winrm_use_https"] is True
    assert api_page.json()[0]["winrm_batch_size"] == 25


def test_worker_run_once_and_state() -> None:
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
            "asset_id": "srv-worker",
        },
    )

    run_resp = client.post("/worker/run-once")
    assert run_resp.status_code == 200

    targets_resp = client.get("/worker/targets")
    assert targets_resp.status_code == 200
    row = targets_resp.json()[0]
    assert row["target_id"] == "col-worker"
    assert "failure_streak" in row

    events_resp = client.get("/assets/srv-worker/events")
    assert events_resp.status_code == 200
    assert any(e["source"].startswith("agentless_") for e in events_resp.json())


def test_dedup_batch_ingest() -> None:
    client.post(
        "/assets",
        json={"id": "win-01", "name": "win-01", "asset_type": "server", "location": "R2"},
    )

    payload = {
        "events": [
            {"asset_id": "win-01", "source": "windows_eventlog", "message": "EventID=6008", "severity": "critical"},
            {"asset_id": "win-01", "source": "windows_eventlog", "message": "EventID=6008", "severity": "critical"},
        ]
    }
    ingest_resp = client.post("/ingest/events", json=payload)
    assert ingest_resp.status_code == 200
    assert ingest_resp.json()["accepted"] == 1




def test_winrm_pull_uses_target_options() -> None:
    class DummyResult:
        status_code = 0
        std_err = b""
        std_out = b'{"RecordId": 20, "Id": 1, "LogName": "Security", "ProviderName": "Test", "LevelDisplayName": "Information", "Message": "ok"}'

    class DummySession:
        def __init__(self, endpoint, auth, transport, server_cert_validation):
            self.endpoint = endpoint
            self.auth = auth
            self.transport = transport
            self.server_cert_validation = server_cert_validation

        def run_ps(self, ps):
            DummyWinRM.last_ps = ps
            return DummyResult()

    class DummyWinRM:
        last_ps = ""
        Session = DummySession

    import sys

    sys.modules["winrm"] = DummyWinRM
    client.post(
        "/assets",
        json={"id": "win-cursor", "name": "win-cursor", "asset_type": "server", "location": "R9"},
    )

    target = main_module.service.upsert_collector_target(
        main_module.CollectorTarget(
            id="col-opt",
            name="opt",
            address="10.0.0.10",
            collector_type=main_module.CollectorType.winrm,
            port=5986,
            username="u",
            password="p",
            poll_interval_sec=30,
            enabled=True,
            asset_id="win-cursor",
            winrm_transport="kerberos",
            winrm_use_https=True,
            winrm_validate_tls=True,
            winrm_event_logs="Security",
            winrm_batch_size=10,
        )
    )

    rows, cursor = main_module.worker._pull_winrm_records(target, "19")
    assert cursor == "20"
    assert rows[0]["LogName"] == "Security"
    assert "LogName=@('Security')" in DummyWinRM.last_ps
    assert "Select-Object -First 10" in DummyWinRM.last_ps

def test_winrm_real_pull_path_with_mock() -> None:
    client.post(
        "/assets",
        json={"id": "win-cursor", "name": "win-cursor", "asset_type": "server", "location": "R9"},
    )
    client.post(
        "/collectors",
        json={
            "id": "col-winrm",
            "name": "WinRM target",
            "address": "127.0.0.1",
            "collector_type": "winrm",
            "port": 5985,
            "username": "u",
            "password": "p",
            "poll_interval_sec": 10,
            "enabled": True,
            "asset_id": "win-cursor",
        },
    )

    def fake_pull(target, last_cursor):
        rows = [
            {
                "RecordId": 11,
                "Id": 6008,
                "LogName": "System",
                "ProviderName": "EventLog",
                "LevelDisplayName": "Critical",
                "Message": "Unexpected shutdown",
            }
        ]
        return rows, "11"

    main_module.worker._pull_winrm_records = fake_pull  # type: ignore[attr-defined]

    run_resp = client.post("/worker/run-once")
    assert run_resp.status_code == 200
    assert run_resp.json()["accepted"] >= 1

    targets = client.get("/worker/targets").json()
    target = [t for t in targets if t["target_id"] == "col-winrm"][0]
    assert target["last_cursor"] == "11"

    events_resp = client.get("/assets/win-cursor/events")
    assert any("RecordId=11" in e["message"] for e in events_resp.json())
