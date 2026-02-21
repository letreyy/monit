from pathlib import Path
import sys

import pytest
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
    assert api_page.json()[0]["password"] == "********"
    assert api_page.json()[0]["ssh_log_path"] == "/var/log/syslog"
    assert api_page.json()[0]["snmp_community"] == "********"


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


def test_collector_password_encryption_roundtrip() -> None:
    Fernet = pytest.importorskip("cryptography.fernet").Fernet

    from app.security import FernetSecretCodec

    db_path = Path("data/test_encrypt.db")
    if db_path.exists():
        db_path.unlink()

    codec = FernetSecretCodec(Fernet.generate_key().decode("utf-8"))
    storage = SQLiteStorage(str(db_path), secret_codec=codec)
    service = MonitoringService(storage)

    service.upsert_asset(main_module.Asset(id="srv-sec", name="srv-sec", asset_type=main_module.AssetType.server))
    service.upsert_collector_target(
        main_module.CollectorTarget(
            id="col-sec",
            name="secure",
            address="10.0.0.20",
            collector_type=main_module.CollectorType.winrm,
            port=5985,
            username="admin",
            password="super-secret",
            poll_interval_sec=60,
            enabled=True,
            asset_id="srv-sec",
        )
    )

    # Stored value in DB is encrypted token, not plaintext
    with storage._connect() as conn:  # noqa: SLF001
        row = conn.execute("SELECT password FROM collector_targets WHERE id = ?", ("col-sec",)).fetchone()
    assert row is not None
    assert row["password"] != "super-secret"

    targets = service.list_collector_targets()
    assert targets[0].password == "super-secret"

    if db_path.exists():
        db_path.unlink()


def test_ssh_pull_uses_target_commands_with_mock() -> None:
    class DummyStream:
        def __init__(self, payload: bytes):
            self.payload = payload

        def read(self):
            return self.payload

    class DummySSHClient:
        last_commands: list[str] = []

        def set_missing_host_key_policy(self, _):
            return None

        def connect(self, **kwargs):
            self.kwargs = kwargs

        def exec_command(self, cmd, timeout=None):
            DummySSHClient.last_commands.append(cmd)
            if "loadavg" in cmd:
                return None, DummyStream(b"0.11 0.22 0.33 1/100 111\n"), DummyStream(b"")
            return None, DummyStream(b"line1\nline2\n"), DummyStream(b"")

        def close(self):
            return None

    class DummyParamiko:
        SSHClient = DummySSHClient

        @staticmethod
        def AutoAddPolicy():
            return object()

    sys.modules["paramiko"] = DummyParamiko

    client.post(
        "/assets",
        json={"id": "linux-01", "name": "linux-01", "asset_type": "server", "location": "R5"},
    )
    target = main_module.service.upsert_collector_target(
        main_module.CollectorTarget(
            id="col-ssh",
            name="ssh target",
            address="10.0.0.30",
            collector_type=main_module.CollectorType.ssh,
            port=22,
            username="u",
            password="p",
            poll_interval_sec=30,
            enabled=True,
            asset_id="linux-01",
            ssh_metrics_command="cat /proc/loadavg",
            ssh_log_path="/var/log/messages",
            ssh_tail_lines=2,
        )
    )

    rows, cursor = main_module.worker._pull_ssh_snapshot(target, "5")
    assert int(cursor) >= 6
    assert any(r.get("metric") == "load1" for r in rows)
    assert any("line1" in r.get("message", "") for r in rows)
    assert DummySSHClient.last_commands[0] == "cat /proc/loadavg"
    assert DummySSHClient.last_commands[1] == "tail -n 2 /var/log/messages"



def test_snmp_pull_uses_oids_with_mock() -> None:
    class DummyOID:
        def __init__(self, oid):
            self.oid = oid

        def __str__(self):
            return self.oid

    class DummyValue:
        def __init__(self, val):
            self.val = val

        def __str__(self):
            return str(self.val)

        def __float__(self):
            return float(self.val)

    class DummyCommunityData:
        def __init__(self, community, mpModel=1):
            self.community = community
            self.mpModel = mpModel

    class DummyUdpTransportTarget:
        def __init__(self, endpoint, timeout=1, retries=0):
            self.endpoint = endpoint
            self.timeout = timeout
            self.retries = retries

    def dummy_getCmd(*args, **kwargs):
        oid = args[-1].oid
        value = 123 if oid.endswith("3.0") else 7
        def _iter():
            yield None, None, None, [(DummyOID(oid), DummyValue(value))]
        return _iter()

    class DummyObjectIdentity:
        def __init__(self, oid):
            self.oid = oid

    class DummyObjectType:
        def __init__(self, identity):
            self.oid = identity.oid

    class DummyHLAPI:
        CommunityData = DummyCommunityData
        ContextData = object
        ObjectIdentity = DummyObjectIdentity
        ObjectType = DummyObjectType
        SnmpEngine = object
        UdpTransportTarget = DummyUdpTransportTarget
        getCmd = staticmethod(dummy_getCmd)

    sys.modules["pysnmp.hlapi"] = DummyHLAPI

    client.post("/assets", json={"id": "sw-01", "name": "sw-01", "asset_type": "network", "location": "R6"})
    target = main_module.service.upsert_collector_target(
        main_module.CollectorTarget(
            id="col-snmp",
            name="snmp target",
            address="10.0.0.40",
            collector_type=main_module.CollectorType.snmp,
            port=161,
            username="ignored",
            password="ignored",
            poll_interval_sec=30,
            enabled=True,
            asset_id="sw-01",
            snmp_community="public",
            snmp_version="2c",
            snmp_oids="1.3.6.1.2.1.1.3.0,1.3.6.1.2.1.1.5.0",
        )
    )

    rows, cursor = main_module.worker._pull_snmp_snapshot(target, "10")
    assert int(cursor) >= 11
    assert len(rows) == 2
    assert rows[0]["metric"].startswith("snmp_")
    assert rows[0]["value"] is not None



def test_worker_health_endpoint() -> None:
    resp = client.get("/worker/health")
    assert resp.status_code == 200
    payload = resp.json()
    assert "status" in payload
    assert "tracked" in payload
    assert "failed" in payload


def test_dashboard_includes_worker_health_widget() -> None:
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "Events Overview" in resp.text
    assert "Logs Trend" in resp.text
    assert "Recent Alerts" in resp.text
    assert "/dashboard/data" in resp.text
    assert "/static/dashboard.js" in resp.text
    assert "worker-health" in resp.text
    assert "flt-role" in resp.text
    assert "nav-collectors" in resp.text
    assert "/worker/health" in resp.text




def test_dashboard_data_endpoint_shape() -> None:
    resp = client.get("/dashboard/data")
    assert resp.status_code == 200
    payload = resp.json()
    assert "overview" in payload
    assert "sources" in payload
    assert "trend" in payload
    assert "top_assets" in payload
    assert "recent_alerts" in payload



def test_dashboard_data_filters() -> None:
    client.post(
        "/assets",
        json={"id": "srv-df", "name": "srv-df", "asset_type": "server", "location": "R12"},
    )
    client.post(
        "/events",
        json={
            "asset_id": "srv-df",
            "source": "windows_eventlog",
            "message": "EventID=4625 failed",
            "severity": "warning",
        },
    )
    client.post(
        "/events",
        json={
            "asset_id": "srv-df",
            "source": "syslog",
            "message": "kernel: info",
            "severity": "info",
        },
    )

    payload = client.get("/dashboard/data?asset_id=srv-df&source=windows_eventlog&period_days=30").json()
    assert payload["overview"]["events_filtered"] >= 1
    assert payload["sources"]["windows"] >= 1
    assert payload["sources"]["syslog"] == 0
    assert payload["filters"]["asset_id"] == "srv-df"
    assert payload["filters"]["source"] == "windows_eventlog"



def test_dashboard_data_role_permissions() -> None:
    viewer = client.get("/dashboard/data", headers={"X-Role": "viewer"}).json()
    operator = client.get("/dashboard/data", headers={"X-Role": "operator"}).json()

    assert viewer["role"] == "viewer"
    assert viewer["permissions"]["show_recent_alerts"] is False
    assert viewer["permissions"]["show_worker_health"] is False

    assert operator["role"] == "operator"
    assert operator["permissions"]["show_recent_alerts"] is True
    assert operator["permissions"]["show_worker_health"] is True

def test_worker_history_endpoint_has_rows_after_run_once() -> None:
    client.post(
        "/assets",
        json={"id": "srv-hist", "name": "srv-hist", "asset_type": "server", "location": "R7"},
    )
    client.post(
        "/collectors",
        json={
            "id": "col-hist",
            "name": "History target",
            "address": "127.0.0.1",
            "collector_type": "ssh",
            "port": 1,
            "username": "u",
            "password": "p",
            "poll_interval_sec": 10,
            "enabled": True,
            "asset_id": "srv-hist",
        },
    )

    run_resp = client.post("/worker/run-once")
    assert run_resp.status_code == 200

    hist_resp = client.get("/worker/history?limit=5")
    assert hist_resp.status_code == 200
    payload = hist_resp.json()
    assert isinstance(payload, list)
    assert len(payload) >= 1
    assert payload[0]["target_id"] == "col-hist"

    filtered = client.get("/worker/history?limit=5&target_id=col-hist&collector_type=ssh").json()
    assert len(filtered) >= 1
    assert all(row["target_id"] == "col-hist" for row in filtered)
    assert all(row["collector_type"] == "ssh" for row in filtered)


def test_ui_diagnostics_page() -> None:
    resp = client.get("/ui/diagnostics?collector_type=ssh&has_error=1")
    assert resp.status_code == 200
    assert "Worker diagnostics" in resp.text
    assert "/worker/history" in resp.text
    assert "Apply" in resp.text
    assert "Summary:" in resp.text
    assert "Download filtered CSV" in resp.text
    assert "/worker/diagnostics/summary" in resp.text
    assert "/worker/diagnostics/stream" in resp.text
    assert "new EventSource" in resp.text


def test_worker_history_persists_in_storage() -> None:
    db_path = Path("data/test_history.db")
    if db_path.exists():
        db_path.unlink()

    storage = SQLiteStorage(str(db_path))
    service = MonitoringService(storage)
    worker = AgentlessWorker(service)

    service.upsert_asset(main_module.Asset(id="srv-p", name="srv-p", asset_type=main_module.AssetType.server))
    service.upsert_collector_target(
        main_module.CollectorTarget(
            id="col-p",
            name="persist",
            address="127.0.0.1",
            collector_type=main_module.CollectorType.ssh,
            port=1,
            username="u",
            password="p",
            poll_interval_sec=10,
            enabled=True,
            asset_id="srv-p",
        )
    )

    worker.run_once()
    history = service.list_worker_history(limit=10, target_id="col-p")
    assert len(history) >= 1

    if db_path.exists():
        db_path.unlink()


def test_worker_history_csv_export() -> None:
    client.post(
        "/assets",
        json={"id": "srv-csv", "name": "srv-csv", "asset_type": "server", "location": "R8"},
    )
    client.post(
        "/collectors",
        json={
            "id": "col-csv",
            "name": "CSV target",
            "address": "127.0.0.1",
            "collector_type": "ssh",
            "port": 1,
            "username": "u",
            "password": "p",
            "poll_interval_sec": 10,
            "enabled": True,
            "asset_id": "srv-csv",
        },
    )

    client.post("/worker/run-once")

    csv_resp = client.get("/worker/history.csv?target_id=col-csv&collector_type=ssh")
    assert csv_resp.status_code == 200
    assert "text/plain" in csv_resp.headers["content-type"]
    assert "ts,target_id,collector_type,accepted_events" in csv_resp.text
    assert "\"col-csv\"" in csv_resp.text



def test_storage_migrates_events_fingerprint_column() -> None:
    db_path = Path("data/test_migration.db")
    if db_path.exists():
        db_path.unlink()

    import sqlite3

    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id TEXT NOT NULL,
            source TEXT NOT NULL,
            message TEXT NOT NULL,
            metric TEXT,
            value REAL,
            severity TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE assets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            location TEXT
        )
        """
    )
    conn.commit()
    conn.close()

    storage = SQLiteStorage(str(db_path))

    with storage._connect() as check:  # noqa: SLF001
        cols = [row["name"] for row in check.execute("PRAGMA table_info(events)").fetchall()]

    assert "fingerprint" in cols

    if db_path.exists():
        db_path.unlink()










def test_collector_and_ingest_endpoints_forbid_viewer_header_role() -> None:
    client.post(
        "/assets",
        json={"id": "srv-rbac-op", "name": "srv-rbac-op", "asset_type": "server", "location": "R13"},
    )
    viewer = {"X-Role": "viewer"}

    create_col = client.post(
        "/collectors",
        headers=viewer,
        json={
            "id": "col-rbac-v",
            "name": "rbac deny",
            "address": "127.0.0.1",
            "collector_type": "ssh",
            "port": 22,
            "username": "u",
            "password": "p",
            "poll_interval_sec": 10,
            "enabled": True,
            "asset_id": "srv-rbac-op",
        },
    )
    assert create_col.status_code == 403

    one_event = client.post(
        "/events",
        headers=viewer,
        json={
            "asset_id": "srv-rbac-op",
            "source": "syslog",
            "message": "viewer denied",
            "severity": "info",
        },
    )
    assert one_event.status_code == 403

    batch = client.post(
        "/ingest/events",
        headers=viewer,
        json={
            "events": [
                {
                    "asset_id": "srv-rbac-op",
                    "source": "syslog",
                    "message": "viewer denied batch",
                    "severity": "info",
                }
            ]
        },
    )
    assert batch.status_code == 403


def test_collector_and_ingest_endpoints_allow_operator_header_role() -> None:
    client.post(
        "/assets",
        json={"id": "srv-rbac-op2", "name": "srv-rbac-op2", "asset_type": "server", "location": "R14"},
    )
    operator = {"X-Role": "operator"}

    create_col = client.post(
        "/collectors",
        headers=operator,
        json={
            "id": "col-rbac-ok",
            "name": "rbac allow",
            "address": "127.0.0.1",
            "collector_type": "ssh",
            "port": 22,
            "username": "u",
            "password": "p",
            "poll_interval_sec": 10,
            "enabled": True,
            "asset_id": "srv-rbac-op2",
        },
    )
    assert create_col.status_code == 200

    list_col = client.get("/collectors", headers=operator)
    assert list_col.status_code == 200

    one_event = client.post(
        "/events",
        headers=operator,
        json={
            "asset_id": "srv-rbac-op2",
            "source": "syslog",
            "message": "operator allowed",
            "severity": "info",
        },
    )
    assert one_event.status_code == 200

    batch = client.post(
        "/ingest/events",
        headers=operator,
        json={
            "events": [
                {
                    "asset_id": "srv-rbac-op2",
                    "source": "syslog",
                    "message": "operator allowed batch",
                    "severity": "info",
                }
            ]
        },
    )
    assert batch.status_code == 200



def test_auth_login_and_session_cookie_role_resolution() -> None:
    resp = client.post("/auth/login", data={"username": "ops", "password": "ops123"})
    assert resp.status_code == 200
    assert "auth_session" in resp.cookies

    whoami = client.get("/auth/whoami", cookies={"auth_session": resp.cookies.get("auth_session")})
    assert whoami.status_code == 200
    assert whoami.json()["role"] == "operator"


def test_auth_audit_admin_only() -> None:
    viewer = client.get("/auth/audit", headers={"X-Role": "viewer"})
    assert viewer.status_code == 403

    admin = client.get("/auth/audit", headers={"X-Role": "admin"})
    assert admin.status_code == 200
    assert isinstance(admin.json(), list)

def test_auth_whoami_with_role_header() -> None:
    resp = client.get("/auth/whoami", headers={"X-Role": "operator"})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["role"] == "operator"


def test_worker_sensitive_endpoints_forbid_viewer_header_role() -> None:
    headers = {"X-Role": "viewer"}
    assert client.get("/worker/history", headers=headers).status_code == 403
    assert client.get("/worker/history.csv", headers=headers).status_code == 403
    assert client.get("/worker/targets", headers=headers).status_code == 403
    assert client.post("/worker/run-once", headers=headers).status_code == 403


def test_worker_sensitive_endpoints_allow_operator_header_role() -> None:
    headers = {"X-Role": "operator"}
    assert client.get("/worker/history", headers=headers).status_code == 200
    assert client.get("/worker/history.csv", headers=headers).status_code == 200
    assert client.get("/worker/targets", headers=headers).status_code == 200
    assert client.post("/worker/run-once", headers=headers).status_code == 200

def test_worker_sensitive_endpoints_query_role_disabled_by_default() -> None:
    assert client.get("/worker/history?role=viewer").status_code == 200
    assert client.get("/worker/history.csv?role=viewer").status_code == 200
    assert client.get("/worker/targets?role=viewer").status_code == 200
    assert client.post("/worker/run-once?role=viewer").status_code == 200


def test_ui_diagnostics_viewer_role_hides_raw_history() -> None:
    resp = client.get("/ui/diagnostics", headers={"X-Role": "viewer"})
    assert resp.status_code == 200
    assert "Current role: <b>viewer</b>" in resp.text
    assert "raw history limited by role" in resp.text

def test_worker_diagnostics_stream_endpoint() -> None:
    client.post(
        "/assets",
        json={"id": "srv-stream", "name": "srv-stream", "asset_type": "server", "location": "R11"},
    )
    client.post(
        "/collectors",
        json={
            "id": "col-stream",
            "name": "Stream target",
            "address": "127.0.0.1",
            "collector_type": "ssh",
            "port": 1,
            "username": "u",
            "password": "p",
            "poll_interval_sec": 10,
            "enabled": True,
            "asset_id": "srv-stream",
        },
    )
    client.post("/worker/run-once")

    with client.stream("GET", "/worker/diagnostics/stream?collector_type=ssh&tick_sec=1&max_events=1") as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        first_chunk = ""
        for chunk in resp.iter_text():
            if chunk.strip():
                first_chunk = chunk
                break

    assert "event: diagnostics" in first_chunk
    assert "\"summary\"" in first_chunk
    assert "\"trend\"" in first_chunk

def test_worker_diagnostics_data_endpoints() -> None:
    client.post(
        "/assets",
        json={"id": "srv-data", "name": "srv-data", "asset_type": "server", "location": "R10"},
    )
    client.post(
        "/collectors",
        json={
            "id": "col-data",
            "name": "Data target",
            "address": "127.0.0.1",
            "collector_type": "ssh",
            "port": 1,
            "username": "u",
            "password": "p",
            "poll_interval_sec": 10,
            "enabled": True,
            "asset_id": "srv-data",
        },
    )
    client.post("/worker/run-once")

    summary = client.get("/worker/diagnostics/summary?collector_type=ssh").json()
    assert "runs" in summary
    assert "by_type" in summary

    trend = client.get("/worker/diagnostics/trend?collector_type=ssh").json()
    assert "points" in trend

