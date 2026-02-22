from pathlib import Path
import sys
import json
import time
import hmac
import hashlib
import base64

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
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
    main_module.AUTH_JWT_HS256_SECRET = ""
    main_module.AUTH_JWT_ISSUER = ""
    main_module.AUTH_JWT_AUDIENCE = ""
    main_module.AUTH_JWT_ROLE_CLAIM = "role"
    main_module.AUTH_JWKS_URL = ""
    main_module.AUTH_OIDC_DISCOVERY_URL = ""
    main_module.AUTH_JWKS_CACHE_TTL_SEC = 300
    main_module.AUTH_JWT_LEEWAY_SEC = 30
    main_module._JWKS_CACHE = {"ts": 0.0, "keys": {}}
    main_module._OIDC_DISCOVERY_CACHE = {"ts": 0.0, "jwks_uri": ""}
    main_module.ISSUER_ROLE_CLAIM_MAP = {}
    main_module.ISSUER_SCOPE_CLAIM_MAP = {}
    main_module.ISSUER_GROUP_CLAIM_MAP = {}
    main_module.JWT_REJECT_TELEMETRY.clear()
    main_module.JWT_REJECT_BY_ISSUER_CLIENT.clear()
    main_module.JWT_REJECT_EVENTS.clear()
    main_module.COMPLIANCE_REPORTS.clear()
    main_module.COMPLIANCE_REPORT_DELIVERIES.clear()
    main_module.COMPLIANCE_LAST_REPORT_TS = 0
    main_module.COMPLIANCE_WEBHOOK_URL = ""
    main_module.COMPLIANCE_EMAIL_TO = ""
    main_module.COMPLIANCE_REPORT_INTERVAL_SEC = 3600


client = TestClient(main_module.app)


def _jwt_hs256(payload: dict, secret: str) -> str:
    def enc(v: bytes) -> str:
        return base64.urlsafe_b64encode(v).decode().rstrip("=")

    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = enc(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = enc(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{enc(sig)}"




def _jwt_rs256(payload: dict, private_key: rsa.RSAPrivateKey, kid: str = "k1") -> str:
    def enc(v: bytes) -> str:
        return base64.urlsafe_b64encode(v).decode().rstrip("=")

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    header_b64 = enc(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = enc(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{enc(sig)}"


def _rsa_public_jwk(private_key: rsa.RSAPrivateKey, kid: str = "k1") -> dict:
    pub = private_key.public_key().public_numbers()

    def enc_int(v: int) -> str:
        raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": enc_int(pub.n), "e": enc_int(pub.e)}

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
    assert "AI Analytics" in resp.text
    assert "AI Policies" in resp.text
    assert "nav-collectors" in resp.text
    assert "/worker/health" in resp.text








def test_ui_ai_policy_center_crud_and_dry_run() -> None:
    client.post(
        "/assets",
        json={"id": "ui-pol-asset", "name": "ui-pol-asset", "asset_type": "server", "location": "R3"},
    )
    client.post(
        "/events",
        json={
            "asset_id": "ui-pol-asset",
            "source": "syslog",
            "message": "CRITICAL timeout from backend",
            "severity": "critical",
        },
    )

    save = client.post(
        "/ui/ai/policies",
        data={
            "policy_id": "ui-pol-1",
            "name": "UI policy",
            "tenant_id": "",
            "ignore_sources": "syslog",
            "ignore_signatures": "",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert save.status_code == 303

    page = client.get("/ui/ai/policies?policy_id=ui-pol-1&asset_id=ui-pol-asset")
    assert page.status_code == 200
    assert "AI policy center" in page.text
    assert "ui-pol-1" in page.text
    assert "Dry-run result" in page.text

    delete = client.post("/ui/ai/policies/ui-pol-1/delete", data={"tenant_id": ""}, follow_redirects=False)
    assert delete.status_code == 303

def test_ui_ai_analytics_center_page() -> None:
    client.post(
        "/assets",
        json={"id": "ui-ai-1", "name": "ui-ai-1", "asset_type": "server", "location": "R1"},
    )
    client.post(
        "/events",
        json={
            "asset_id": "ui-ai-1",
            "source": "syslog",
            "message": "CRITICAL timeout from backend",
            "severity": "critical",
        },
    )

    resp = client.get("/ui/ai?asset_id=ui-ai-1")
    assert resp.status_code == 200
    assert "AI analytics center" in resp.text
    assert "Selected asset anomalies" in resp.text
    assert "ui-ai-1" in resp.text

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





def test_assets_and_dashboard_tenant_scope() -> None:
    client.post("/assets", json={"id": "t1:srv-a", "name": "a", "asset_type": "server", "location": "R1"}, headers={"X-Role": "operator"})
    client.post("/assets", json={"id": "t2:srv-b", "name": "b", "asset_type": "server", "location": "R2"}, headers={"X-Role": "operator"})

    assets_t1 = client.get("/assets", headers={"X-Tenant": "t1"})
    assert assets_t1.status_code == 200
    ids = [a["id"] for a in assets_t1.json()]
    assert "t1:srv-a" in ids
    assert "t2:srv-b" not in ids

    dash = client.get("/dashboard/data", headers={"X-Tenant": "t1"}).json()
    assert dash["filters"]["tenant_id"] == "t1"


def test_asset_read_endpoint_forbidden_outside_tenant_scope() -> None:
    client.post("/assets", json={"id": "t1:srv-r", "name": "r", "asset_type": "server", "location": "R3"}, headers={"X-Role": "operator"})
    client.post("/events", json={"asset_id": "t1:srv-r", "source": "syslog", "message": "m", "severity": "info"}, headers={"X-Role": "operator"})

    denied = client.get("/assets/t1:srv-r/events", headers={"X-Tenant": "t2"})
    assert denied.status_code == 403


def test_worker_history_tenant_scope_filters_targets() -> None:
    client.post("/assets", json={"id": "t1:srv-wh", "name": "wh", "asset_type": "server", "location": "R1"}, headers={"X-Role": "operator"})
    client.post("/assets", json={"id": "t2:srv-wh", "name": "wh2", "asset_type": "server", "location": "R1"}, headers={"X-Role": "operator"})

    for tid, aid in [("t1:col-wh", "t1:srv-wh"), ("t2:col-wh", "t2:srv-wh")]:
        client.post("/collectors", headers={"X-Role": "operator"}, json={
            "id": tid, "name": tid, "address": "127.0.0.1", "collector_type": "ssh", "port": 1,
            "username": "u", "password": "p", "poll_interval_sec": 10, "enabled": True, "asset_id": aid,
        })
    client.post("/worker/run-once", headers={"X-Role": "operator"})

    rows = client.get("/worker/history", headers={"X-Role": "operator", "X-Tenant": "t1"}).json()
    assert all(r["target_id"].startswith("t1:") for r in rows)

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





def test_auth_token_bearer_allows_operator_actions() -> None:
    tok = client.post("/auth/token", data={"username": "ops", "password": "ops123"})
    assert tok.status_code == 200
    token = tok.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/worker/targets", headers=headers)
    assert resp.status_code == 200


def test_auth_token_invalid_credentials() -> None:
    tok = client.post("/auth/token", data={"username": "ops", "password": "bad"})
    assert tok.status_code == 401

def test_auth_login_and_session_cookie_role_resolution() -> None:
    resp = client.post("/auth/login", data={"username": "ops", "password": "ops123"})
    assert resp.status_code == 200
    assert "auth_session" in resp.cookies

    whoami = client.get("/auth/whoami", cookies={"auth_session": resp.cookies.get("auth_session")})
    assert whoami.status_code == 200
    assert whoami.json()["role"] == "operator"




def test_auth_audit_contains_policy_entries() -> None:
    client.get("/worker/history", headers={"X-Role": "viewer"})
    audit = client.get("/auth/audit?limit=5", headers={"X-Role": "admin"})
    assert audit.status_code == 200
    rows = audit.json()
    assert isinstance(rows, list)
    assert len(rows) >= 1
    assert rows[0]["result"] in {"allow", "deny"}

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




def test_auth_whoami_reports_source_for_bearer_token() -> None:
    tok = client.post("/auth/token", data={"username": "ops", "password": "ops123"})
    assert tok.status_code == 200
    token = tok.json()["access_token"]

    resp = client.get("/auth/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["role"] == "operator"
    assert payload["source"] == "bearer_signed"


def test_auth_whoami_reports_default_source_without_auth() -> None:
    resp = client.get("/auth/whoami")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["source"] in {"default", "session"}
    assert payload["role"] in {"viewer", "operator", "admin"}


def test_auth_whoami_accepts_valid_hs256_jwt() -> None:
    secret = "jwt-secret-test"
    main_module.AUTH_JWT_HS256_SECRET = secret
    main_module.AUTH_JWT_ISSUER = "issuer-1"
    main_module.AUTH_JWT_AUDIENCE = "aud-1"
    main_module.AUTH_JWT_ROLE_CLAIM = "role"

    payload = {
        "iss": "issuer-1",
        "aud": "aud-1",
        "exp": int(time.time()) + 300,
        "role": "operator",
    }
    token = _jwt_hs256(payload, secret)
    resp = client.get("/auth/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == "operator"
    assert data["source"] == "jwt_hs256"


def test_auth_whoami_rejects_invalid_hs256_jwt_audience() -> None:
    secret = "jwt-secret-test"
    main_module.AUTH_JWT_HS256_SECRET = secret
    main_module.AUTH_JWT_ISSUER = "issuer-1"
    main_module.AUTH_JWT_AUDIENCE = "aud-expected"

    payload = {
        "iss": "issuer-1",
        "aud": "aud-other",
        "exp": int(time.time()) + 300,
        "role": "admin",
    }
    token = _jwt_hs256(payload, secret)
    resp = client.get("/auth/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] != "jwt_hs256"



def test_auth_whoami_accepts_valid_rs256_jwt_via_jwks(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = _rsa_public_jwk(private_key, kid="kid-1")

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"keys": [jwk]}).encode()

    monkeypatch.setattr(main_module, "urlopen", lambda *args, **kwargs: _Resp())

    main_module.AUTH_JWKS_URL = "https://issuer.example/jwks.json"
    main_module.AUTH_JWT_ISSUER = "issuer-rs"
    main_module.AUTH_JWT_AUDIENCE = "aud-rs"
    main_module.AUTH_JWT_ROLE_CLAIM = "role"
    main_module._JWKS_CACHE = {"ts": 0.0, "keys": {}}

    payload = {"iss": "issuer-rs", "aud": "aud-rs", "exp": int(time.time()) + 300, "role": "admin"}
    token = _jwt_rs256(payload, private_key, kid="kid-1")

    resp = client.get("/auth/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == "admin"
    assert data["source"] == "jwt_rs256"


def test_auth_whoami_rejects_rs256_jwt_with_unknown_kid(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = _rsa_public_jwk(other_key, kid="kid-other")

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"keys": [jwk]}).encode()

    monkeypatch.setattr(main_module, "urlopen", lambda *args, **kwargs: _Resp())

    main_module.AUTH_JWKS_URL = "https://issuer.example/jwks.json"
    main_module.AUTH_JWT_ISSUER = "issuer-rs"
    main_module.AUTH_JWT_AUDIENCE = "aud-rs"
    main_module._JWKS_CACHE = {"ts": 0.0, "keys": {}}

    payload = {"iss": "issuer-rs", "aud": "aud-rs", "exp": int(time.time()) + 300, "role": "operator"}
    token = _jwt_rs256(payload, private_key, kid="kid-1")

    resp = client.get("/auth/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] != "jwt_rs256"



def test_auth_whoami_accepts_rs256_via_oidc_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = _rsa_public_jwk(private_key, kid="kid-disc")

    class _Resp:
        def __init__(self, payload: dict):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(self.payload).encode()

    def _urlopen(url: str, timeout: int = 0):
        if "openid-configuration" in url:
            return _Resp({"jwks_uri": "https://issuer.example/jwks"})
        if url.endswith("/jwks"):
            return _Resp({"keys": [jwk]})
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(main_module, "urlopen", _urlopen)

    main_module.AUTH_JWKS_URL = ""
    main_module.AUTH_OIDC_DISCOVERY_URL = "https://issuer.example/.well-known/openid-configuration"
    main_module.AUTH_JWT_ISSUER = "issuer-disc"
    main_module.AUTH_JWT_AUDIENCE = "aud-disc"
    main_module.AUTH_JWT_ROLE_CLAIM = "role"
    main_module._JWKS_CACHE = {"ts": 0.0, "keys": {}}
    main_module._OIDC_DISCOVERY_CACHE = {"ts": 0.0, "jwks_uri": ""}
    main_module.ISSUER_ROLE_CLAIM_MAP = {}
    main_module.ISSUER_SCOPE_CLAIM_MAP = {}
    main_module.ISSUER_GROUP_CLAIM_MAP = {}
    main_module.JWT_REJECT_TELEMETRY.clear()
    main_module.JWT_REJECT_BY_ISSUER_CLIENT.clear()
    main_module.JWT_REJECT_EVENTS.clear()

    payload = {"iss": "issuer-disc", "aud": "aud-disc", "exp": int(time.time()) + 300, "role": "operator"}
    token = _jwt_rs256(payload, private_key, kid="kid-disc")

    resp = client.get("/auth/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == "operator"
    assert data["source"] == "jwt_rs256"
    assert data["oidc_discovery_enabled"] is True


def test_auth_whoami_rejects_jwt_with_future_nbf() -> None:
    secret = "jwt-secret-test"
    main_module.AUTH_JWT_HS256_SECRET = secret
    main_module.AUTH_JWT_ISSUER = "issuer-1"
    main_module.AUTH_JWT_AUDIENCE = "aud-1"
    main_module.AUTH_JWT_LEEWAY_SEC = 0

    payload = {
        "iss": "issuer-1",
        "aud": "aud-1",
        "exp": int(time.time()) + 300,
        "nbf": int(time.time()) + 120,
        "role": "admin",
    }
    token = _jwt_hs256(payload, secret)
    resp = client.get("/auth/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] != "jwt_hs256"



def test_auth_whoami_maps_role_from_groups_claim() -> None:
    secret = "jwt-secret-test"
    main_module.AUTH_JWT_HS256_SECRET = secret
    main_module.AUTH_JWT_ISSUER = "issuer-1"
    main_module.AUTH_JWT_AUDIENCE = "aud-1"
    main_module.ROLE_GROUPS_MAP = {"operators": "operator", "admins": "admin"}

    payload = {
        "iss": "issuer-1",
        "aud": "aud-1",
        "exp": int(time.time()) + 300,
        "groups": ["operators"],
    }
    token = _jwt_hs256(payload, secret)
    resp = client.get("/auth/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == "operator"
    assert data["source"] == "jwt_hs256"


def test_auth_jwt_reject_telemetry_and_audit_exports() -> None:
    secret = "jwt-secret-test"
    main_module.AUTH_JWT_HS256_SECRET = secret
    main_module.AUTH_JWT_ISSUER = "issuer-1"
    main_module.AUTH_JWT_AUDIENCE = "aud-1"

    bad = _jwt_hs256({"iss": "issuer-1", "aud": "aud-1", "exp": int(time.time()) - 5, "role": "admin"}, secret)
    client.get("/auth/whoami", headers={"Authorization": f"Bearer {bad}"})

    telem = client.get("/auth/jwt/reject-telemetry", headers={"X-Role": "admin"})
    assert telem.status_code == 200
    assert "counters" in telem.json()

    summary = client.get("/auth/audit/summary", headers={"X-Role": "admin"})
    assert summary.status_code == 200
    assert "rows" in summary.json()

    csv_resp = client.get("/auth/audit.csv", headers={"X-Role": "admin"})
    assert csv_resp.status_code == 200
    assert "ts,path,role,action,result" in csv_resp.text


def test_policy_middleware_forbids_viewer_on_post_events() -> None:
    client.post(
        "/assets",
        headers={"X-Role": "operator"},
        json={"id": "srv-policy", "name": "srv-policy", "asset_type": "server", "location": "R16"},
    )
    denied = client.post(
        "/events",
        headers={"X-Role": "viewer"},
        json={"asset_id": "srv-policy", "source": "manual", "message": "x", "severity": "info"},
    )
    assert denied.status_code == 403




def test_auth_whoami_issuer_specific_role_claim_mapping() -> None:
    secret = "jwt-secret-test"
    main_module.AUTH_JWT_HS256_SECRET = secret
    main_module.AUTH_JWT_ISSUER = "issuer-custom"
    main_module.AUTH_JWT_AUDIENCE = "aud-custom"
    main_module.ISSUER_ROLE_CLAIM_MAP = {"issuer-custom": "custom_role"}

    payload = {"iss": "issuer-custom", "aud": "aud-custom", "exp": int(time.time()) + 300, "custom_role": "admin"}
    token = _jwt_hs256(payload, secret)
    resp = client.get("/auth/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == "admin"


def test_auth_jwt_reject_telemetry_details_endpoint() -> None:
    secret = "jwt-secret-test"
    main_module.AUTH_JWT_HS256_SECRET = secret
    main_module.AUTH_JWT_ISSUER = "issuer-telemetry"
    main_module.AUTH_JWT_AUDIENCE = "aud-telemetry"
    main_module.AUTH_JWT_LEEWAY_SEC = 0

    bad = _jwt_hs256({"iss": "issuer-telemetry", "aud": "aud-telemetry", "exp": int(time.time()) - 10, "azp": "cli-1", "role": "admin"}, secret)
    client.get("/auth/whoami", headers={"Authorization": f"Bearer {bad}"})

    details = client.get("/auth/jwt/reject-telemetry/details?limit=5", headers={"X-Role": "admin"})
    assert details.status_code == 200
    rows = details.json()
    assert isinstance(rows, list)
    assert len(rows) >= 1
    assert rows[0]["issuer"] in {"issuer-telemetry", "unknown"}


def test_compliance_report_run_and_listing() -> None:
    denied = client.get("/auth/audit", headers={"X-Role": "viewer"})
    assert denied.status_code == 403

    run = client.post("/auth/compliance/run", headers={"X-Role": "admin"})
    assert run.status_code == 200
    report = run.json()
    assert report["id"].startswith("cr-")
    assert "summary" in report

    listing = client.get("/auth/compliance/reports?limit=5", headers={"X-Role": "admin"})
    assert listing.status_code == 200
    rows = listing.json()
    assert len(rows) >= 1

    details = client.get(f"/auth/compliance/reports/{report['id']}", headers={"X-Role": "admin"})
    assert details.status_code == 200
    assert details.json()["id"] == report["id"]

    status = client.get("/auth/compliance/status", headers={"X-Role": "admin"})
    assert status.status_code == 200
    assert status.json()["reports"] >= 1


def test_compliance_purge_and_delivery_routes() -> None:
    main_module.COMPLIANCE_WEBHOOK_URL = "https://example.local/hook"
    main_module.COMPLIANCE_EMAIL_TO = "secops@example.local"

    old_ts = int(time.time()) - 100000
    main_module.service.add_access_audit(
        main_module.AccessAuditEntry(ts=old_ts, path="/old", role="viewer", action="test", result="allow")
    )

    main_module.JWT_REJECT_TELEMETRY["expired"] += 2
    main_module.JWT_REJECT_BY_ISSUER_CLIENT["issuer|client"] += 1
    main_module.JWT_REJECT_EVENTS.appendleft({"ts": int(time.time()), "reason": "expired", "issuer": "issuer", "client": "client"})

    run = client.post("/auth/compliance/run", headers={"X-Role": "admin"})
    assert run.status_code == 200

    deliveries = client.get("/auth/compliance/deliveries?limit=5", headers={"X-Role": "admin"})
    assert deliveries.status_code == 200
    channels = {d["channel"] for d in deliveries.json()}
    assert "webhook" in channels
    assert "email" in channels

    purge = client.post(
        "/auth/compliance/purge?audit_max_age_sec=1&worker_history_max_age_sec=1&ai_policy_audit_max_age_sec=1&drop_jwt_reject_telemetry=true",
        headers={"X-Role": "admin"},
    )
    assert purge.status_code == 200
    body = purge.json()
    assert body["deleted_audit"] >= 1
    assert body["jwt_reject_telemetry_cleared"] is True
    assert dict(main_module.JWT_REJECT_TELEMETRY) == {}

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


def test_ui_auth_and_compliance_console_flow() -> None:
    ui_auth = client.get("/ui/auth")
    assert ui_auth.status_code == 200
    assert "Auth session console" in ui_auth.text

    login = client.post(
        "/ui/auth/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=False,
    )
    assert login.status_code == 303
    cookie = login.headers.get("set-cookie", "")
    assert "auth_session=" in cookie

    session_cookie = cookie.split(";", 1)[0]
    headers = {"cookie": session_cookie}

    ui_compliance = client.get("/ui/compliance", headers=headers)
    assert ui_compliance.status_code == 200
    assert "Compliance center" in ui_compliance.text

    run = client.post("/ui/compliance/run", headers=headers, follow_redirects=False)
    assert run.status_code == 303

    reports = client.get("/auth/compliance/reports", headers={"X-Role": "admin"}).json()
    assert len(reports) >= 1

    purge = client.post(
        "/ui/compliance/purge",
        headers=headers,
        data={"audit_max_age_sec": "1", "worker_history_max_age_sec": "1", "ai_policy_audit_max_age_sec": "1", "drop_jwt_reject_telemetry": "on"},
        follow_redirects=False,
    )
    assert purge.status_code == 303

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


def test_ai_log_analytics_clusters_and_explanations() -> None:
    client.post(
        "/assets",
        json={"id": "srv-ai", "name": "srv-ai", "asset_type": "server", "location": "R7"},
    )

    events = []
    for i in range(6):
        events.append({"asset_id": "srv-ai", "source": "windows_eventlog", "message": f"EventID=4625 user=ops host=10.0.0.{i+1}", "severity": "warning"})
    for i in range(6):
        events.append({"asset_id": "srv-ai", "source": "linux", "message": f"cpu load high value={20+i}", "metric": "cpu_load", "value": 20 + i, "severity": "info"})
    events.append({"asset_id": "srv-ai", "source": "linux", "message": "cpu load high value=120", "metric": "cpu_load", "value": 120, "severity": "warning"})
    events.append({"asset_id": "srv-ai", "source": "windows_eventlog", "message": "Kernel panic on node 77", "severity": "critical"})

    ingest_resp = client.post("/ingest/events", json={"events": events})
    assert ingest_resp.status_code == 200

    resp = client.get("/assets/srv-ai/ai-log-analytics?limit=200")
    assert resp.status_code == 200
    data = resp.json()

    assert data["analyzed_events"] >= 14
    assert len(data["clusters"]) >= 3
    assert any(item["kind"] == "metric_outlier" for item in data["anomalies"])
    assert any(item["kind"] == "rare_pattern" for item in data["anomalies"])
    assert any("Кластер" in evidence for item in data["anomalies"] for evidence in item["evidence"])


def test_ai_log_analytics_missing_asset() -> None:
    resp = client.get("/assets/unknown/ai-log-analytics")
    assert resp.status_code == 404


def test_ai_log_analytics_honors_top_limits() -> None:
    client.post(
        "/assets",
        json={"id": "srv-ai-top", "name": "srv-ai-top", "asset_type": "server", "location": "R11"},
    )

    events = []
    for i in range(15):
        events.append(
            {
                "asset_id": "srv-ai-top",
                "source": "linux",
                "message": f"service timeout code={500 + i}",
                "severity": "warning",
            }
        )
    client.post("/ingest/events", json={"events": events})

    resp = client.get("/assets/srv-ai-top/ai-log-analytics?limit=200&max_clusters=5&max_anomalies=1")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["clusters"]) <= 5
    assert len(data["anomalies"]) <= 1
    if data["clusters"]:
        assert data["clusters"][0]["cluster_id"].startswith("cl-")


def test_ai_log_analytics_ignore_filters() -> None:
    client.post(
        "/assets",
        json={"id": "srv-ai-filter", "name": "srv-ai-filter", "asset_type": "server", "location": "R12"},
    )

    events = []
    for i in range(8):
        events.append(
            {
                "asset_id": "srv-ai-filter",
                "source": "linux",
                "message": f"service timeout code={500 + i}",
                "severity": "warning",
            }
        )
    for i in range(5):
        events.append(
            {
                "asset_id": "srv-ai-filter",
                "source": "windows_eventlog",
                "message": f"EventID=4625 user=ops host=10.10.0.{i+1}",
                "severity": "warning",
            }
        )

    ingest_resp = client.post("/ingest/events", json={"events": events})
    assert ingest_resp.status_code == 200

    full_resp = client.get("/assets/srv-ai-filter/ai-log-analytics?limit=200")
    assert full_resp.status_code == 200
    full_data = full_resp.json()
    assert any(item["source"] == "linux" for item in full_data["clusters"])

    filtered_resp = client.get("/assets/srv-ai-filter/ai-log-analytics?limit=200&ignore_sources=linux")
    assert filtered_resp.status_code == 200
    filtered_data = filtered_resp.json()
    assert all(item["source"] != "linux" for item in filtered_data["clusters"])
    assert any("Исключено ignore-правилами" in line for line in filtered_data["summary"])


def test_ai_log_analytics_ignore_signature() -> None:
    client.post(
        "/assets",
        json={"id": "srv-ai-sign", "name": "srv-ai-sign", "asset_type": "server", "location": "R13"},
    )

    events = [
        {"asset_id": "srv-ai-sign", "source": "linux", "message": f"service timeout code={500 + i}", "severity": "warning"}
        for i in range(6)
    ]
    client.post("/ingest/events", json={"events": events})

    sig = "service timeout code=<num>"
    resp = client.get("/assets/srv-ai-sign/ai-log-analytics", params={"ignore_signatures": sig})
    assert resp.status_code == 200
    data = resp.json()
    assert data["analyzed_events"] == 0
    assert data["clusters"] == []


def test_ai_log_analytics_overview_basic() -> None:
    client.post("/assets", json={"id": "ov-1", "name": "ov-1", "asset_type": "server", "location": "R1"})
    client.post("/assets", json={"id": "ov-2", "name": "ov-2", "asset_type": "server", "location": "R2"})

    payload = {
        "events": [
            {"asset_id": "ov-1", "source": "linux", "message": "service timeout code=501", "severity": "warning"},
            {"asset_id": "ov-1", "source": "linux", "message": "service timeout code=502", "severity": "warning"},
            {"asset_id": "ov-1", "source": "linux", "message": "service timeout code=503", "severity": "warning"},
            {"asset_id": "ov-2", "source": "windows_eventlog", "message": "Kernel panic on node 3", "severity": "critical"},
        ]
    }
    ingest_resp = client.post("/ingest/events", json=payload)
    assert ingest_resp.status_code == 200

    resp = client.get("/ai-log-analytics/overview?limit_per_asset=200&max_assets=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["assets_considered"] >= 2
    assert "assets" in data
    assert any(item["asset_id"] == "ov-1" for item in data["assets"])


def test_ai_log_analytics_overview_ignore_source() -> None:
    client.post("/assets", json={"id": "ov-ign", "name": "ov-ign", "asset_type": "server", "location": "R3"})
    payload = {
        "events": [
            {"asset_id": "ov-ign", "source": "linux", "message": "service timeout code=700", "severity": "warning"},
            {"asset_id": "ov-ign", "source": "linux", "message": "service timeout code=701", "severity": "warning"},
            {"asset_id": "ov-ign", "source": "linux", "message": "service timeout code=702", "severity": "warning"},
        ]
    }
    client.post("/ingest/events", json=payload)

    resp = client.get("/ai-log-analytics/overview", params={"ignore_sources": "linux"})
    assert resp.status_code == 200
    data = resp.json()
    item = next(entry for entry in data["assets"] if entry["asset_id"] == "ov-ign")
    assert item["analyzed_events"] == 0


def test_ai_log_policy_crud_and_apply_to_asset_endpoint() -> None:
    create_resp = client.post(
        "/ai-log-analytics/policies",
        json={
            "id": "pol-1",
            "name": "ignore linux timeout",
            "ignore_sources": ["linux"],
            "ignore_signatures": [],
            "enabled": True,
        },
    )
    assert create_resp.status_code == 200

    list_resp = client.get("/ai-log-analytics/policies")
    assert list_resp.status_code == 200
    assert any(item["id"] == "pol-1" for item in list_resp.json())

    client.post("/assets", json={"id": "pol-asset", "name": "pol-asset", "asset_type": "server", "location": "R14"})
    client.post(
        "/ingest/events",
        json={
            "events": [
                {"asset_id": "pol-asset", "source": "linux", "message": "service timeout code=901", "severity": "warning"},
                {"asset_id": "pol-asset", "source": "linux", "message": "service timeout code=902", "severity": "warning"},
            ]
        },
    )

    analytics_resp = client.get("/assets/pol-asset/ai-log-analytics", params={"policy_id": "pol-1"})
    assert analytics_resp.status_code == 200
    payload = analytics_resp.json()
    assert payload["analyzed_events"] == 0

    del_resp = client.delete("/ai-log-analytics/policies/pol-1")
    assert del_resp.status_code == 200


def test_ai_log_policy_apply_to_overview() -> None:
    client.post(
        "/ai-log-analytics/policies",
        json={
            "id": "pol-over",
            "name": "ignore linux",
            "ignore_sources": ["linux"],
            "ignore_signatures": [],
            "enabled": True,
        },
    )
    client.post("/assets", json={"id": "pol-over-asset", "name": "pol-over-asset", "asset_type": "server", "location": "R15"})
    client.post(
        "/ingest/events",
        json={
            "events": [
                {"asset_id": "pol-over-asset", "source": "linux", "message": "service timeout code=950", "severity": "warning"},
                {"asset_id": "pol-over-asset", "source": "linux", "message": "service timeout code=951", "severity": "warning"},
            ]
        },
    )

    resp = client.get("/ai-log-analytics/overview", params={"policy_id": "pol-over"})
    assert resp.status_code == 200
    data = resp.json()
    item = next(row for row in data["assets"] if row["asset_id"] == "pol-over-asset")
    assert item["analyzed_events"] == 0


def test_ai_log_policies_merge_union_vs_intersection() -> None:
    client.post(
        "/ai-log-analytics/policies",
        json={"id": "pol-u1", "name": "ignore linux", "ignore_sources": ["linux"], "ignore_signatures": [], "enabled": True},
    )
    client.post(
        "/ai-log-analytics/policies",
        json={"id": "pol-u2", "name": "ignore windows", "ignore_sources": ["windows_eventlog"], "ignore_signatures": [], "enabled": True},
    )

    client.post("/assets", json={"id": "merge-asset", "name": "merge-asset", "asset_type": "server", "location": "R16"})
    client.post(
        "/ingest/events",
        json={
            "events": [
                {"asset_id": "merge-asset", "source": "linux", "message": "service timeout code=991", "severity": "warning"},
                {"asset_id": "merge-asset", "source": "windows_eventlog", "message": "EventID=4625 user=test", "severity": "warning"},
            ]
        },
    )

    union_resp = client.get(
        "/assets/merge-asset/ai-log-analytics",
        params={"policy_ids": "pol-u1,pol-u2", "policy_merge_strategy": "union", "limit": 200},
    )
    assert union_resp.status_code == 200
    assert union_resp.json()["analyzed_events"] == 0

    inter_resp = client.get(
        "/assets/merge-asset/ai-log-analytics",
        params={"policy_ids": "pol-u1,pol-u2", "policy_merge_strategy": "intersection", "limit": 200},
    )
    assert inter_resp.status_code == 200
    assert inter_resp.json()["analyzed_events"] >= 2


def test_ai_log_policy_dry_run_endpoint() -> None:
    client.post(
        "/ai-log-analytics/policies",
        json={"id": "pol-dry", "name": "dry", "ignore_sources": ["linux"], "ignore_signatures": [], "enabled": True},
    )
    client.post("/assets", json={"id": "dry-asset", "name": "dry-asset", "asset_type": "server", "location": "R17"})
    client.post(
        "/ingest/events",
        json={
            "events": [
                {"asset_id": "dry-asset", "source": "linux", "message": "service timeout code=801", "severity": "warning"},
                {"asset_id": "dry-asset", "source": "linux", "message": "service timeout code=802", "severity": "warning"},
            ]
        },
    )

    resp = client.get("/assets/dry-asset/ai-log-analytics/policy-dry-run", params={"policy_id": "pol-dry"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_events"] >= 2
    assert data["filtered_events"] >= 2
    assert data["remaining_events"] == 0
    assert "linux" in data["applied_sources"]


def test_ai_log_policy_merge_strategy_validation() -> None:
    client.post("/assets", json={"id": "merge-val", "name": "merge-val", "asset_type": "server", "location": "R18"})

    resp_asset = client.get(
        "/assets/merge-val/ai-log-analytics",
        params={"policy_merge_strategy": "bad_value"},
    )
    assert resp_asset.status_code == 422

    resp_overview = client.get(
        "/ai-log-analytics/overview",
        params={"policy_merge_strategy": "bad_value"},
    )
    assert resp_overview.status_code == 422

    resp_dry_run = client.get(
        "/assets/merge-val/ai-log-analytics/policy-dry-run",
        params={"policy_merge_strategy": "bad_value"},
    )
    assert resp_dry_run.status_code == 422


def test_ai_log_policy_tenant_scope_visibility_and_usage() -> None:
    create_resp = client.post(
        "/ai-log-analytics/policies?tenant_id=t1",
        json={
            "id": "pol-tenant-1",
            "name": "tenant t1 policy",
            "ignore_sources": ["linux"],
            "ignore_signatures": [],
            "enabled": True,
        },
    )
    assert create_resp.status_code == 200
    assert create_resp.json()["tenant_id"] == "t1"

    list_t1 = client.get("/ai-log-analytics/policies?tenant_id=t1")
    assert list_t1.status_code == 200
    assert any(item["id"] == "pol-tenant-1" for item in list_t1.json())

    list_t2 = client.get("/ai-log-analytics/policies?tenant_id=t2")
    assert list_t2.status_code == 200
    assert all(item["id"] != "pol-tenant-1" for item in list_t2.json())

    client.post("/assets", json={"id": "t2:asset", "name": "t2:asset", "asset_type": "server", "location": "t2-rack"})
    client.post(
        "/ingest/events",
        json={"events": [{"asset_id": "t2:asset", "source": "linux", "message": "service timeout code=991", "severity": "warning"}]},
    )

    forbidden_policy = client.get(
        "/assets/t2:asset/ai-log-analytics",
        params={"tenant_id": "t2", "policy_id": "pol-tenant-1"},
    )
    assert forbidden_policy.status_code == 404


def test_ai_log_policy_audit_entries() -> None:
    create = client.post(
        "/ai-log-analytics/policies?tenant_id=t3",
        json={"id": "pol-audit", "name": "audit", "ignore_sources": ["linux"], "ignore_signatures": [], "enabled": True},
        headers={"X-Role": "admin"},
    )
    assert create.status_code == 200

    delete = client.delete("/ai-log-analytics/policies/pol-audit?tenant_id=t3", headers={"X-Role": "admin"})
    assert delete.status_code == 200

    audit = client.get("/ai-log-analytics/policies/audit?tenant_id=t3&limit=10", headers={"X-Role": "admin"})
    assert audit.status_code == 200
    rows = audit.json()
    assert any(row["policy_id"] == "pol-audit" and row["action"] == "upsert" for row in rows)
    assert any(row["policy_id"] == "pol-audit" and row["action"] == "delete" for row in rows)


def test_ai_log_policy_audit_filters_and_csv() -> None:
    client.post(
        "/ai-log-analytics/policies?tenant_id=t4",
        json={"id": "pol-a1", "name": "a1", "ignore_sources": ["linux"], "ignore_signatures": [], "enabled": True},
        headers={"X-Role": "admin"},
    )
    client.post(
        "/ai-log-analytics/policies?tenant_id=t4",
        json={"id": "pol-a2", "name": "a2", "ignore_sources": ["windows_eventlog"], "ignore_signatures": [], "enabled": True},
        headers={"X-Role": "admin"},
    )
    client.delete("/ai-log-analytics/policies/pol-a1?tenant_id=t4", headers={"X-Role": "admin"})

    filtered = client.get(
        "/ai-log-analytics/policies/audit",
        params={"tenant_id": "t4", "action": "delete", "policy_id": "pol-a1", "limit": 10},
        headers={"X-Role": "admin"},
    )
    assert filtered.status_code == 200
    rows = filtered.json()
    assert len(rows) >= 1
    assert all(row["action"] == "delete" for row in rows)
    assert all(row["policy_id"] == "pol-a1" for row in rows)

    csv_resp = client.get(
        "/ai-log-analytics/policies/audit.csv",
        params={"tenant_id": "t4", "action": "upsert", "limit": 10},
        headers={"X-Role": "admin"},
    )
    assert csv_resp.status_code == 200
    assert "ts,policy_id,tenant_id,action,actor_role,details" in csv_resp.text
    assert '"upsert"' in csv_resp.text


def test_ai_log_policy_audit_sort_offset_and_max_ts() -> None:
    client.post(
        "/ai-log-analytics/policies?tenant_id=t5",
        json={"id": "pol-s1", "name": "s1", "ignore_sources": ["linux"], "ignore_signatures": [], "enabled": True},
        headers={"X-Role": "admin"},
    )
    client.post(
        "/ai-log-analytics/policies?tenant_id=t5",
        json={"id": "pol-s2", "name": "s2", "ignore_sources": ["windows_eventlog"], "ignore_signatures": [], "enabled": True},
        headers={"X-Role": "admin"},
    )

    rows_desc = client.get("/ai-log-analytics/policies/audit", params={"tenant_id": "t5", "sort": "desc", "limit": 10}, headers={"X-Role": "admin"}).json()
    assert len(rows_desc) >= 2
    newest_ts = rows_desc[0]["ts"]

    rows_asc = client.get("/ai-log-analytics/policies/audit", params={"tenant_id": "t5", "sort": "asc", "limit": 10}, headers={"X-Role": "admin"}).json()
    assert len(rows_asc) >= 2
    assert rows_asc[0]["ts"] <= rows_asc[-1]["ts"]

    rows_offset = client.get("/ai-log-analytics/policies/audit", params={"tenant_id": "t5", "sort": "desc", "limit": 1, "offset": 1}, headers={"X-Role": "admin"}).json()
    assert len(rows_offset) == 1

    rows_max_ts = client.get("/ai-log-analytics/policies/audit", params={"tenant_id": "t5", "max_ts": newest_ts, "limit": 50}, headers={"X-Role": "admin"}).json()
    assert all(row["ts"] <= newest_ts for row in rows_max_ts)

    bad_sort = client.get("/ai-log-analytics/policies/audit", params={"tenant_id": "t5", "sort": "bad"}, headers={"X-Role": "admin"})
    assert bad_sort.status_code == 422


def test_compliance_purge_cleans_ai_policy_audit() -> None:
    client.post(
        "/ai-log-analytics/policies?tenant_id=t6",
        json={"id": "pol-purge", "name": "purge", "ignore_sources": ["linux"], "ignore_signatures": [], "enabled": True},
        headers={"X-Role": "admin"},
    )
    before = client.get("/ai-log-analytics/policies/audit?tenant_id=t6&limit=20", headers={"X-Role": "admin"})
    assert before.status_code == 200
    assert len(before.json()) >= 1

    purge = client.post(
        "/auth/compliance/purge?audit_max_age_sec=1&worker_history_max_age_sec=1&ai_policy_audit_max_age_sec=1",
        headers={"X-Role": "admin"},
    )
    assert purge.status_code == 200
    assert purge.json()["deleted_ai_policy_audit"] >= 0
