import os
import json
import asyncio
import hmac
import time
import hashlib
import base64
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from urllib.request import urlopen
from urllib.error import URLError

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, StreamingResponse, JSONResponse
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.models import (
    AccessAuditEntry,
    Alert,
    Asset,
    AssetType,
    CollectorTarget,
    CollectorType,
    CollectorTargetPublic,
    CorrelationInsight,
    Event,
    EventBatch,
    IngestSummary,
    LogAnalyticsInsight,
    LogAnalyticsOverview,
    LogAnalyticsPolicy,
    LogAnalyticsPolicyAuditDetails,
    LogAnalyticsPolicyAuditEntry,
    LogAnalyticsPolicyAuditEntryParsed,
    LogAnalyticsPolicyDryRun,
    PolicyMergeStrategy,
    Overview,
    Recommendation,
    Severity,
)
from app.services import MonitoringService
from app.worker import AgentlessWorker

service = MonitoringService()
WORKER_TICK_SEC = float(os.getenv("WORKER_TICK_SEC", "2"))
WORKER_TIMEOUT_SEC = float(os.getenv("WORKER_TIMEOUT_SEC", "2"))
worker = AgentlessWorker(service, tick_sec=WORKER_TICK_SEC, timeout_sec=WORKER_TIMEOUT_SEC)
ENABLE_AGENTLESS_WORKER = os.getenv("ENABLE_AGENTLESS_WORKER", "1") == "1"
ALLOW_QUERY_ROLE = os.getenv("ALLOW_QUERY_ROLE", "0") == "1"
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "auth_session")
SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me-in-production")
SESSION_TTL_SEC = int(os.getenv("SESSION_TTL_SEC", "86400"))
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "change-token-secret")
TOKEN_TTL_SEC = int(os.getenv("TOKEN_TTL_SEC", "3600"))
AUTH_JWT_HS256_SECRET = os.getenv("AUTH_JWT_HS256_SECRET", "")
AUTH_JWT_ISSUER = os.getenv("AUTH_JWT_ISSUER", "")
AUTH_JWT_AUDIENCE = os.getenv("AUTH_JWT_AUDIENCE", "")
AUTH_JWT_ROLE_CLAIM = os.getenv("AUTH_JWT_ROLE_CLAIM", "role")
AUTH_JWKS_URL = os.getenv("AUTH_JWKS_URL", "")
AUTH_OIDC_DISCOVERY_URL = os.getenv("AUTH_OIDC_DISCOVERY_URL", "")
AUTH_JWKS_CACHE_TTL_SEC = int(os.getenv("AUTH_JWKS_CACHE_TTL_SEC", "300"))
AUTH_JWT_LEEWAY_SEC = int(os.getenv("AUTH_JWT_LEEWAY_SEC", "30"))
AUTH_ROLE_SCOPES_MAP = os.getenv("AUTH_ROLE_SCOPES_MAP", "monitor.admin:admin,monitor.write:operator,monitor.read:viewer")
AUTH_ROLE_GROUPS_MAP = os.getenv("AUTH_ROLE_GROUPS_MAP", "admins:admin,operators:operator,viewers:viewer")
AUTH_TENANT_HEADER_NAME = os.getenv("AUTH_TENANT_HEADER_NAME", "X-Tenant")
AUTH_SCOPE_CLAIM = os.getenv("AUTH_SCOPE_CLAIM", "scope")
AUTH_GROUPS_CLAIM = os.getenv("AUTH_GROUPS_CLAIM", "groups")
AUTH_ISSUER_ROLE_CLAIM_MAP = os.getenv("AUTH_ISSUER_ROLE_CLAIM_MAP", "")
AUTH_ISSUER_SCOPE_CLAIM_MAP = os.getenv("AUTH_ISSUER_SCOPE_CLAIM_MAP", "")
AUTH_ISSUER_GROUP_CLAIM_MAP = os.getenv("AUTH_ISSUER_GROUP_CLAIM_MAP", "")
COMPLIANCE_REPORT_INTERVAL_SEC = int(os.getenv("COMPLIANCE_REPORT_INTERVAL_SEC", "3600"))
COMPLIANCE_REPORT_RETENTION = int(os.getenv("COMPLIANCE_REPORT_RETENTION", "100"))
COMPLIANCE_WEBHOOK_URL = os.getenv("COMPLIANCE_WEBHOOK_URL", "")
COMPLIANCE_EMAIL_TO = os.getenv("COMPLIANCE_EMAIL_TO", "")


def _load_auth_token_roles() -> dict[str, str]:
    raw = os.getenv("AUTH_TOKENS", "")
    mapping: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        token, role = item.split(":", 1)
        mapping[token.strip()] = role.strip()
    return mapping


def _load_auth_users() -> dict[str, tuple[str, str]]:
    raw = os.getenv("AUTH_USERS", "admin:admin123:admin,ops:ops123:operator,viewer:viewer123:viewer")
    users: dict[str, tuple[str, str]] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        parts = item.split(":")
        if len(parts) != 3:
            continue
        username, password, role = parts
        users[username.strip()] = (password.strip(), role.strip())
    return users


def _session_sign(payload: str) -> str:
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return sig


def _create_session_value(role: str) -> str:
    exp = int(time.time()) + SESSION_TTL_SEC
    payload = f"{role}|{exp}"
    sig = _session_sign(payload)
    raw = f"{payload}|{sig}".encode()
    return base64.urlsafe_b64encode(raw).decode()


def _parse_session_value(value: str | None) -> str | None:
    if not value:
        return None
    try:
        decoded = base64.urlsafe_b64decode(value.encode()).decode()
        role, exp_s, sig = decoded.split("|", 2)
        payload = f"{role}|{exp_s}"
        if not hmac.compare_digest(sig, _session_sign(payload)):
            return None
        if int(exp_s) < int(time.time()):
            return None
        return _normalize_role(role)
    except Exception:
        return None


def _token_sign(payload: str) -> str:
    return hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode())




_JWKS_CACHE: dict[str, object] = {"ts": 0.0, "keys": {}}
_OIDC_DISCOVERY_CACHE: dict[str, object] = {"ts": 0.0, "jwks_uri": ""}


def _b64url_decode_to_int(value: str) -> int:
    return int.from_bytes(_b64url_decode(value), byteorder="big")


def _parse_role_mapping(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        key, role = item.split(":", 1)
        norm = role.strip()
        if norm in {"viewer", "operator", "admin"}:
            out[key.strip()] = norm
    return out




def _parse_claim_name_mapping(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        issuer, claim = item.split(":", 1)
        if issuer.strip() and claim.strip():
            out[issuer.strip()] = claim.strip()
    return out


def _jwt_unverified_claims(token: str | None) -> dict[str, object]:
    if not token or token.count(".") != 2:
        return {}
    try:
        _h, payload_b64, _s = token.split(".")
        payload = json.loads(_b64url_decode(payload_b64).decode())
        if isinstance(payload, dict):
            return payload
    except Exception:
        return {}
    return {}

ROLE_PRIORITY = {"viewer": 0, "operator": 1, "admin": 2}
ROLE_SCOPES_MAP = _parse_role_mapping(AUTH_ROLE_SCOPES_MAP)
ROLE_GROUPS_MAP = _parse_role_mapping(AUTH_ROLE_GROUPS_MAP)
ISSUER_ROLE_CLAIM_MAP = _parse_claim_name_mapping(AUTH_ISSUER_ROLE_CLAIM_MAP)
ISSUER_SCOPE_CLAIM_MAP = _parse_claim_name_mapping(AUTH_ISSUER_SCOPE_CLAIM_MAP)
ISSUER_GROUP_CLAIM_MAP = _parse_claim_name_mapping(AUTH_ISSUER_GROUP_CLAIM_MAP)
JWT_REJECT_TELEMETRY: Counter[str] = Counter()
JWT_REJECT_BY_ISSUER_CLIENT: Counter[str] = Counter()
JWT_REJECT_EVENTS: deque[dict[str, str | int]] = deque(maxlen=500)
COMPLIANCE_REPORTS: deque[dict[str, object]] = deque(maxlen=max(10, COMPLIANCE_REPORT_RETENTION))
COMPLIANCE_REPORT_DELIVERIES: deque[dict[str, object]] = deque(maxlen=500)
COMPLIANCE_LAST_REPORT_TS = 0


def _record_jwt_reject(reason: str, token: str | None = None) -> None:
    JWT_REJECT_TELEMETRY[reason] += 1
    claims = _jwt_unverified_claims(token)
    issuer = str(claims.get("iss", "unknown"))
    client = str(claims.get("azp") or claims.get("client_id") or "unknown")
    JWT_REJECT_BY_ISSUER_CLIENT[f"{issuer}|{client}"] += 1
    JWT_REJECT_EVENTS.appendleft({"ts": int(time.time()), "reason": reason, "issuer": issuer, "client": client})


def _role_from_claim_mapping(payload: dict[str, object]) -> str | None:
    issuer = str(payload.get("iss", ""))
    role_claim = ISSUER_ROLE_CLAIM_MAP.get(issuer, AUTH_JWT_ROLE_CLAIM)
    scope_claim = ISSUER_SCOPE_CLAIM_MAP.get(issuer, AUTH_SCOPE_CLAIM)
    group_claim = ISSUER_GROUP_CLAIM_MAP.get(issuer, AUTH_GROUPS_CLAIM)

    role_val = payload.get(role_claim)
    if isinstance(role_val, list):
        for v in role_val:
            n = _normalize_role(str(v))
            if n != "viewer" or str(v) == "viewer":
                return n
    elif role_val is not None:
        role = _normalize_role(str(role_val))
        if role != "viewer" or str(role_val) == "viewer":
            return role

    scopes = payload.get(scope_claim)
    scope_values: list[str] = []
    if isinstance(scopes, str):
        scope_values = [x.strip() for x in scopes.split(" ") if x.strip()]
    elif isinstance(scopes, list):
        scope_values = [str(x) for x in scopes]
    mapped = [ROLE_SCOPES_MAP[s] for s in scope_values if s in ROLE_SCOPES_MAP]

    groups = payload.get(group_claim)
    group_values: list[str] = []
    if isinstance(groups, list):
        group_values = [str(x) for x in groups]
    elif isinstance(groups, str):
        group_values = [groups]
    mapped.extend(ROLE_GROUPS_MAP[g] for g in group_values if g in ROLE_GROUPS_MAP)

    if not mapped:
        return None
    return max(mapped, key=lambda r: ROLE_PRIORITY.get(r, 0))


def _resolve_jwks_url() -> str:
    if AUTH_JWKS_URL:
        return AUTH_JWKS_URL
    if not AUTH_OIDC_DISCOVERY_URL:
        return ""

    now = time.time()
    ts = float(_OIDC_DISCOVERY_CACHE.get("ts", 0.0))
    cached = str(_OIDC_DISCOVERY_CACHE.get("jwks_uri", ""))
    if cached and now - ts < max(1, AUTH_JWKS_CACHE_TTL_SEC):
        return cached

    try:
        with urlopen(AUTH_OIDC_DISCOVERY_URL, timeout=3) as resp:  # nosec B310
            doc = json.loads(resp.read().decode())
    except (URLError, TimeoutError, ValueError):
        return cached

    jwks_uri = str(doc.get("jwks_uri", "")).strip()
    if jwks_uri:
        _OIDC_DISCOVERY_CACHE["ts"] = now
        _OIDC_DISCOVERY_CACHE["jwks_uri"] = jwks_uri
        return jwks_uri
    return cached


def _validate_jwt_payload_claims(payload: dict[str, object]) -> bool:
    now = int(time.time())
    leeway = max(0, AUTH_JWT_LEEWAY_SEC)

    exp = int(payload.get("exp", 0))
    if exp <= 0 or exp < now - leeway:
        return False

    nbf = payload.get("nbf")
    if nbf is not None and int(nbf) > now + leeway:
        return False

    iat = payload.get("iat")
    if iat is not None and int(iat) > now + leeway:
        return False

    if AUTH_JWT_ISSUER and payload.get("iss") != AUTH_JWT_ISSUER:
        return False

    aud = payload.get("aud")
    if AUTH_JWT_AUDIENCE:
        if isinstance(aud, list):
            if AUTH_JWT_AUDIENCE not in aud:
                return False
        elif aud != AUTH_JWT_AUDIENCE:
            return False

    return True

def _fetch_jwks_keys(force_refresh: bool = False) -> dict[str, rsa.RSAPublicKey]:
    now = time.time()
    ts = float(_JWKS_CACHE.get("ts", 0.0))
    cached = _JWKS_CACHE.get("keys")
    if cached and now - ts < max(1, AUTH_JWKS_CACHE_TTL_SEC):
        return cached  # type: ignore[return-value]

    jwks_url = _resolve_jwks_url()
    if not jwks_url:
        return {}

    try:
        with urlopen(jwks_url, timeout=3) as resp:  # nosec B310
            payload = json.loads(resp.read().decode())
    except (URLError, TimeoutError, ValueError):
        return cached if isinstance(cached, dict) else {}

    out: dict[str, rsa.RSAPublicKey] = {}
    for key in payload.get("keys", []):
        if key.get("kty") != "RSA":
            continue
        kid = str(key.get("kid", "")).strip()
        n = key.get("n")
        e = key.get("e")
        if not kid or not n or not e:
            continue
        try:
            pub = rsa.RSAPublicNumbers(_b64url_decode_to_int(e), _b64url_decode_to_int(n)).public_key()
            out[kid] = pub
        except Exception:
            continue

    if out:
        _JWKS_CACHE["ts"] = now
        _JWKS_CACHE["keys"] = out
    return out or (cached if isinstance(cached, dict) else {})


def _parse_jwt_rs256_role(token: str | None) -> str | None:
    if not token or token.count(".") != 2 or not _resolve_jwks_url():
        return None
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64).decode())
        if header.get("alg") != "RS256":
            _record_jwt_reject("rs256_bad_alg", token)
            return None
        kid = str(header.get("kid", "")).strip()
        if not kid:
            _record_jwt_reject("rs256_missing_kid", token)
            return None

        keys = _fetch_jwks_keys()
        pub = keys.get(kid)
        if pub is None:
            keys = _fetch_jwks_keys(force_refresh=True)
            pub = keys.get(kid)
        if pub is None:
            _record_jwt_reject("rs256_unknown_kid", token)
            return None

        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = _b64url_decode(sig_b64)
        pub.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())

        payload = json.loads(_b64url_decode(payload_b64).decode())
        if not _validate_jwt_payload_claims(payload):
            _record_jwt_reject("claim_validation_failed", token)
            return None

        role = _role_from_claim_mapping(payload)
        if role is None:
            _record_jwt_reject("role_mapping_failed", token)
            return None
        return role
    except (ValueError, InvalidSignature, TypeError):
        _record_jwt_reject("rs256_parse_or_verify_failed", token)
        return None

def _parse_jwt_hs256_role(token: str | None) -> str | None:
    if not token or token.count(".") != 2 or not AUTH_JWT_HS256_SECRET:
        return None
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(AUTH_JWT_HS256_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
        token_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(token_sig, expected_sig):
            return None

        header = json.loads(_b64url_decode(header_b64).decode())
        if header.get("alg") != "HS256":
            _record_jwt_reject("hs256_bad_alg", token)
            return None

        payload = json.loads(_b64url_decode(payload_b64).decode())
        if not _validate_jwt_payload_claims(payload):
            _record_jwt_reject("claim_validation_failed", token)
            return None

        role = _role_from_claim_mapping(payload)
        if role is None:
            _record_jwt_reject("role_mapping_failed", token)
            return None
        return role
    except Exception:
        _record_jwt_reject("hs256_parse_or_verify_failed", token)
        return None

def _create_bearer_token(role: str) -> str:
    exp = int(time.time()) + TOKEN_TTL_SEC
    payload = f"{role}|{exp}"
    sig = _token_sign(payload)
    raw = f"{payload}|{sig}".encode()
    return base64.urlsafe_b64encode(raw).decode()


def _parse_bearer_token(token: str | None) -> str | None:
    if not token:
        return None
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        role, exp_s, sig = decoded.split("|", 2)
        payload = f"{role}|{exp_s}"
        if not hmac.compare_digest(sig, _token_sign(payload)):
            return None
        if int(exp_s) < int(time.time()):
            return None
        return _normalize_role(role)
    except Exception:
        return None


AUTH_TOKEN_ROLE_MAP = _load_auth_token_roles()
AUTH_USER_MAP = _load_auth_users()




@dataclass
class AuthContext:
    role: str
    source: str
    tenant_id: str | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    if ENABLE_AGENTLESS_WORKER:
        worker.start()
    try:
        yield
    finally:
        worker.stop()


app = FastAPI(title="InfraMind Monitor API", version="0.9.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")



POLICY_RULES: list[tuple[str, str, str, str, str]] = [
    ("GET", "/auth/audit", "admin", "read auth audit", "viewer"),
    ("GET", "/auth/audit.csv", "admin", "export auth audit", "viewer"),
    ("GET", "/auth/audit/summary", "admin", "read auth audit summary", "viewer"),
    ("GET", "/auth/audit/alerts", "admin", "read auth audit alerts", "viewer"),
    ("GET", "/auth/jwt/reject-telemetry", "admin", "read jwt reject telemetry", "viewer"),
    ("GET", "/auth/jwt/reject-telemetry/details", "admin", "read jwt reject telemetry details", "viewer"),
    ("GET", "/auth/compliance/status", "admin", "read compliance status", "viewer"),
    ("GET", "/auth/compliance/reports", "admin", "read compliance reports", "viewer"),
    ("POST", "/auth/compliance/run", "admin", "run compliance report", "viewer"),
    ("POST", "/auth/compliance/purge", "admin", "run compliance purge", "viewer"),
    ("GET", "/auth/compliance/deliveries", "admin", "read compliance deliveries", "viewer"),
    ("GET", "/worker/history", "operator", "read worker history", "admin"),
    ("GET", "/worker/history.csv", "operator", "export worker history", "admin"),
    ("GET", "/worker/targets", "operator", "read worker targets", "admin"),
    ("POST", "/worker/run-once", "operator", "run worker", "admin"),
    ("GET", "/collectors", "operator", "read collectors", "admin"),
    ("POST", "/collectors", "operator", "write collectors", "admin"),
    ("DELETE", "/collectors", "operator", "delete collectors", "admin"),
    ("POST", "/assets", "operator", "write assets", "admin"),
    ("POST", "/events", "operator", "write events", "admin"),
    ("POST", "/ingest/events", "operator", "ingest events", "admin"),
]


def _policy_rule_for_request(method: str, path: str) -> tuple[str, str, str] | None:
    for m, prefix, min_role, action, default_role in POLICY_RULES:
        if method == m and path.startswith(prefix):
            return (min_role, action, default_role)
    return None


@app.middleware("http")
async def auth_context_middleware(request: Request, call_next):
    role_hint = request.query_params.get("role")
    request.state.auth_context = _resolve_auth_context_from_request(request, role_hint, default_role="viewer")
    rule = _policy_rule_for_request(request.method, request.url.path)
    if rule is not None:
        min_role, action, default_role = rule
        try:
            _require_role(request, role_hint, minimum_role=min_role, action=action, default_role=default_role)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    _ensure_scheduled_compliance_report()
    return await call_next(request)


def _asset_exists(asset_id: str) -> bool:
    return any(a.id == asset_id for a in service.list_assets())


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return """
    <html><head>
      <style>
        body { font-family: Inter, Arial, sans-serif; margin:0; background:#f3f5f7; color:#1f2937; }
        .wrap { max-width: 1100px; margin: 24px auto; padding: 0 16px; }
        .hero { background:#fff; border:1px solid #d8dee4; border-radius:12px; padding:20px; }
        .grid { margin-top:14px; display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }
        .card { background:#fff; border:1px solid #d8dee4; border-radius:10px; padding:14px; }
        a { color:#2563eb; text-decoration:none; }
        ul { margin: 8px 0 0 20px; }
      </style>
    </head><body>
      <div class='wrap'>
        <div class='hero'>
          <h1 style='margin:0 0 10px 0'>InfraMind Monitor</h1>
          <p style='margin:0'>Операционная консоль для мониторинга, agentless-сбора, диагностики и AI-подсказок.</p>
        </div>
        <div class='grid'>
          <div class='card'>
            <h3 style='margin:0 0 8px 0'>Операции</h3>
            <ul>
              <li><a href='/dashboard'>Dashboard</a></li>
              <li><a href='/ui/diagnostics'>UI: Worker diagnostics</a></li>
              <li><a href='/worker/status'>Worker status</a></li>
              <li><a href='/worker/targets'>Worker targets</a></li>
            </ul>
          </div>
          <div class='card'>
            <h3 style='margin:0 0 8px 0'>Управление</h3>
            <ul>
              <li><a href='/ui/assets'>UI: Add/List Assets</a></li>
              <li><a href='/ui/events'>UI: Add Event</a></li>
              <li><a href='/ui/collectors'>UI: Agentless Collectors</a></li>
              <li><a href='/ui/auth'>UI: Auth session</a></li>
              <li><a href='/ui/compliance'>UI: Compliance center</a></li>
              <li><a href='/docs'>Swagger UI</a></li>
            </ul>
          </div>
        </div>
      </div>
    </body></html>
    """


def _ui_forbidden_page(title: str, message: str) -> str:
    return f"""
    <html><body style='font-family: Inter, Arial, sans-serif; max-width: 780px; margin: 2rem auto; background:#f3f5f7; color:#111827;'>
      <div style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:20px'>
        <h1 style='margin-top:0'>{title}</h1>
        <p>{message}</p>
        <p><a href='/ui/auth'>Auth UI</a> | <a href='/dashboard'>Dashboard</a> | <a href='/'>Home</a></p>
      </div>
    </body></html>
    """


@app.get("/ui/auth", response_class=HTMLResponse)
def ui_auth(request: Request) -> str:
    context = getattr(request.state, "auth_context", _resolve_auth_context_from_request(request, None, default_role="viewer"))
    err = request.query_params.get("err", "").strip()
    token = ""
    if context.role == "admin":
        token = _create_bearer_token("admin")
    return f"""
    <html><body style='font-family: Inter, Arial, sans-serif; max-width: 900px; margin: 2rem auto; background:#f3f5f7; color:#111827;'>
      <h1>Auth session console</h1>
      <p><a href='/'>← Home</a> | <a href='/ui/compliance'>Compliance UI</a> | <a href='/auth/whoami'>JSON whoami</a></p>
      <div style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:16px;margin-bottom:14px'>
        <h3 style='margin-top:0'>Current auth context</h3>
        <p>Role: <b>{context.role}</b> | Source: <b>{context.source}</b> | Tenant: <b>{context.tenant_id or '-'}</b></p>
        {"<p style='color:#b91c1c'><b>Login error:</b> invalid credentials</p>" if err else ""}
      </div>
      <div style='display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px'>
        <form method='post' action='/ui/auth/login' style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:16px'>
          <h3 style='margin-top:0'>Login (set session cookie)</h3>
          <label>Username <input name='username' required /></label><br/><br/>
          <label>Password <input name='password' type='password' required /></label><br/><br/>
          <button type='submit'>Login</button>
        </form>
        <div style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:16px'>
          <h3 style='margin-top:0'>Quick actions</h3>
          <form method='post' action='/ui/auth/logout' style='margin:0 0 12px 0'><button type='submit'>Logout (clear session)</button></form>
          <p style='margin:0'><b>Bootstrap bearer token (admin preview):</b></p>
          <textarea rows='4' style='width:100%;font-family:monospace' readonly>{token}</textarea>
        </div>
      </div>
    </body></html>
    """


@app.post("/ui/auth/login")
def ui_auth_login(username: str = Form(...), password: str = Form(...)) -> RedirectResponse:
    record = AUTH_USER_MAP.get(username.strip())
    if not record or record[0] != password:
        return RedirectResponse(url="/ui/auth?err=1", status_code=303)
    role = _normalize_role(record[1])
    response = RedirectResponse(url="/ui/auth", status_code=303)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=_create_session_value(role),
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL_SEC,
    )
    return response


@app.post("/ui/auth/logout")
def ui_auth_logout() -> RedirectResponse:
    response = RedirectResponse(url="/ui/auth", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@app.get("/ui/compliance", response_class=HTMLResponse)
def ui_compliance(request: Request, limit: int = 30) -> str:
    context = getattr(request.state, "auth_context", _resolve_auth_context_from_request(request, None, default_role="viewer"))
    if ROLE_ORDER[context.role] < ROLE_ORDER["admin"]:
        return _ui_forbidden_page("Compliance center", "Admin role is required. Login as admin via Auth UI.")

    reports = list(COMPLIANCE_REPORTS)[: max(1, min(limit, 200))]
    deliveries = list(COMPLIANCE_REPORT_DELIVERIES)[: max(1, min(limit, 200))]
    status = {
        "interval": COMPLIANCE_REPORT_INTERVAL_SEC,
        "retention": COMPLIANCE_REPORT_RETENTION,
        "reports": len(COMPLIANCE_REPORTS),
        "last_ts": COMPLIANCE_LAST_REPORT_TS,
        "webhook": bool(COMPLIANCE_WEBHOOK_URL.strip()),
        "email": bool(COMPLIANCE_EMAIL_TO.strip()),
    }
    summary = _build_compliance_summary(limit=1000)
    report_rows = "".join(
        f"<tr><td>{r.get('id')}</td><td>{r.get('trigger')}</td><td>{r.get('ts')}</td><td>{int((r.get('summary') or {}).get('allow', 0))}</td><td>{int((r.get('summary') or {}).get('deny', 0))}</td></tr>"
        for r in reports
    ) or "<tr><td colspan='5'>No reports yet</td></tr>"
    delivery_rows = "".join(
        f"<tr><td>{d.get('ts')}</td><td>{d.get('report_id')}</td><td>{d.get('channel')}</td><td>{d.get('destination')}</td><td>{d.get('status')}</td></tr>"
        for d in deliveries
    ) or "<tr><td colspan='5'>No deliveries yet</td></tr>"

    return f"""
    <html><body style='font-family: Inter, Arial, sans-serif; max-width: 1200px; margin: 2rem auto; background:#f3f5f7; color:#111827;'>
      <h1>Compliance center</h1>
      <p><a href='/dashboard'>← Dashboard</a> | <a href='/ui/auth'>Auth UI</a> | <a href='/auth/compliance/status'>JSON status</a></p>
      <div style='display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px'>
        <div style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:14px'><b>Reports:</b> {status['reports']}</div>
        <div style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:14px'><b>Interval:</b> {status['interval']} sec</div>
        <div style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:14px'><b>Last report ts:</b> {status['last_ts'] or '-'}</div>
      </div>
      <div style='margin-top:12px;background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:14px'>
        <p style='margin:0'><b>Audit summary:</b> rows={summary['rows']}, allow={summary['allow']}, deny={summary['deny']}</p>
      </div>
      <div style='display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:12px'>
        <form method='post' action='/ui/compliance/run' style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:16px'>
          <h3 style='margin-top:0'>Generate report</h3>
          <button type='submit'>Run now</button>
        </form>
        <form method='post' action='/ui/compliance/purge' style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:16px'>
          <h3 style='margin-top:0'>Retention purge</h3>
          <label>Audit max age sec <input type='number' name='audit_max_age_sec' value='2592000' min='0' /></label><br/><br/>
          <label>Worker history max age sec <input type='number' name='worker_history_max_age_sec' value='2592000' min='0' /></label><br/><br/>
          <label>AI policy audit max age sec <input type='number' name='ai_policy_audit_max_age_sec' value='2592000' min='0' /></label><br/><br/>
          <label><input type='checkbox' name='drop_jwt_reject_telemetry'/> Drop JWT reject telemetry</label><br/><br/>
          <button type='submit'>Run purge</button>
        </form>
      </div>
      <h2>Reports</h2>
      <table border='0' cellpadding='8' cellspacing='0' style='width:100%;background:#fff;border:1px solid #d8dee4;border-radius:10px'>
        <thead><tr><th>ID</th><th>Trigger</th><th>TS</th><th>Allow</th><th>Deny</th></tr></thead>
        <tbody>{report_rows}</tbody>
      </table>
      <h2>Deliveries</h2>
      <table border='0' cellpadding='8' cellspacing='0' style='width:100%;background:#fff;border:1px solid #d8dee4;border-radius:10px'>
        <thead><tr><th>TS</th><th>Report ID</th><th>Channel</th><th>Destination</th><th>Status</th></tr></thead>
        <tbody>{delivery_rows}</tbody>
      </table>
    </body></html>
    """


@app.post("/ui/compliance/run")
def ui_compliance_run(request: Request) -> RedirectResponse:
    context = getattr(request.state, "auth_context", _resolve_auth_context_from_request(request, None, default_role="viewer"))
    if ROLE_ORDER[context.role] < ROLE_ORDER["admin"]:
        return RedirectResponse(url="/ui/auth", status_code=303)
    _generate_compliance_report(trigger="manual-ui")
    return RedirectResponse(url="/ui/compliance", status_code=303)


@app.post("/ui/compliance/purge")
def ui_compliance_purge(
    request: Request,
    audit_max_age_sec: int = Form(30 * 24 * 3600),
    worker_history_max_age_sec: int = Form(30 * 24 * 3600),
    ai_policy_audit_max_age_sec: int = Form(30 * 24 * 3600),
    drop_jwt_reject_telemetry: str | None = Form(None),
) -> RedirectResponse:
    context = getattr(request.state, "auth_context", _resolve_auth_context_from_request(request, None, default_role="viewer"))
    if ROLE_ORDER[context.role] < ROLE_ORDER["admin"]:
        return RedirectResponse(url="/ui/auth", status_code=303)
    now = int(time.time())
    audit_min_ts = now - max(0, audit_max_age_sec)
    worker_min_ts_iso = datetime.utcfromtimestamp(now - max(0, worker_history_max_age_sec)).isoformat()
    service.delete_access_audit_older_than(audit_min_ts)
    service.delete_worker_history_older_than(worker_min_ts_iso)
    service.delete_ai_log_policy_audit_older_than(now - max(0, ai_policy_audit_max_age_sec))
    if drop_jwt_reject_telemetry is not None:
        JWT_REJECT_TELEMETRY.clear()
        JWT_REJECT_BY_ISSUER_CLIENT.clear()
        JWT_REJECT_EVENTS.clear()
    return RedirectResponse(url="/ui/compliance", status_code=303)


@app.get("/ui/collectors", response_class=HTMLResponse)
def ui_collectors() -> str:
    asset_options = "".join(f"<option value='{a.id}'>{a.id} ({a.name})</option>" for a in service.list_assets())
    if not asset_options:
        asset_options = "<option value=''>No assets. Create one first.</option>"

    rows = []
    for c in service.list_collector_targets():
        rows.append(
            f"<tr><td>{c.id}</td><td>{c.name}</td><td>{c.collector_type.value}</td><td>{c.address}:{c.port}</td>"
            f"<td>{c.username}</td><td>winrm={c.winrm_transport}/logs={c.winrm_event_logs}; ssh_log={c.ssh_log_path}; snmp={c.snmp_version}:{c.snmp_oids}</td>"
            f"<td>{c.asset_id}</td><td>{'yes' if c.enabled else 'no'}</td>"
            f"<td><form method='post' action='/ui/collectors/{c.id}/delete' style='margin:0'><button type='submit'>Delete</button></form></td></tr>"
        )
    rows_html = "".join(rows) if rows else "<tr><td colspan='9'>No collector targets yet</td></tr>"

    return f"""
    <html><body style='font-family: Inter, Arial, sans-serif; max-width: 1200px; margin: 2rem auto; background:#f3f5f7; color:#111827;'>
      <h1>Agentless Collector Targets</h1>
      <p><a href='/dashboard'>← Dashboard</a> | <a href='/ui/assets'>Manage assets</a></p>
      <form method='post' action='/ui/collectors' style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:16px'>
        <label>ID <input name='target_id' required /></label><br/><br/>
        <label>Name <input name='name' required /></label><br/><br/>
        <label>Type
          <select name='collector_type'>
            <option value='winrm'>winrm (Windows)</option>
            <option value='ssh'>ssh (Linux/Unix)</option>
            <option value='snmp'>snmp (Network/Storage)</option>
          </select>
        </label><br/><br/>
        <label>Address/IP <input name='address' required /></label><br/><br/>
        <label>Port <input name='port' type='number' value='5985' required /></label><br/><br/>
        <label>Username <input name='username' required /></label><br/><br/>
        <label>Password <input name='password' type='password' required /></label><br/><br/>
        <label>WinRM transport
          <select name='winrm_transport'>
            <option value='ntlm'>ntlm</option>
            <option value='basic'>basic</option>
            <option value='kerberos'>kerberos</option>
          </select>
        </label><br/><br/>
        <label>WinRM logs (comma separated) <input name='winrm_event_logs' value='System,Application' /></label><br/><br/>
        <label>WinRM batch size <input name='winrm_batch_size' type='number' value='50' min='1' max='500' /></label><br/><br/>
        <label>WinRM use HTTPS <input name='winrm_use_https' type='checkbox' /></label><br/><br/>
        <label>WinRM validate TLS cert <input name='winrm_validate_tls' type='checkbox' /></label><br/><br/>
        <label>SSH metrics command <input name='ssh_metrics_command' value='cat /proc/loadavg' /></label><br/><br/>
        <label>SSH log path <input name='ssh_log_path' value='/var/log/syslog' /></label><br/><br/>
        <label>SSH tail lines <input name='ssh_tail_lines' type='number' value='50' min='1' max='500' /></label><br/><br/>
        <label>SNMP community <input name='snmp_community' value='public' /></label><br/><br/>
        <label>SNMP version
          <select name='snmp_version'>
            <option value='2c'>2c</option>
            <option value='3'>3</option>
          </select>
        </label><br/><br/>
        <label>SNMP OIDs (comma separated) <input name='snmp_oids' value='1.3.6.1.2.1.1.3.0,1.3.6.1.2.1.1.5.0' /></label><br/><br/>
        <label>Asset
          <select name='asset_id' required>{asset_options}</select>
        </label><br/><br/>
        <label>Poll interval (sec) <input name='poll_interval_sec' type='number' value='60' required /></label><br/><br/>
        <label>Enabled <input name='enabled' type='checkbox' checked /></label><br/><br/>
        <button type='submit'>Save collector target</button>
      </form>
      <h2>Configured targets</h2>
      <table border='0' cellpadding='8' cellspacing='0' style='width:100%;background:#fff;border:1px solid #d8dee4;border-radius:10px'>
        <thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Address</th><th>User</th><th>WinRM options</th><th>Asset</th><th>Enabled</th><th>Actions</th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
      <p><i>Next step: scheduler/worker will auto-poll enabled targets using these settings.</i></p>
    </body></html>
    """


@app.post("/ui/collectors")
def ui_collectors_submit(
    target_id: str = Form(...),
    name: str = Form(...),
    collector_type: str = Form(...),
    address: str = Form(...),
    port: int = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    asset_id: str = Form(...),
    poll_interval_sec: int = Form(60),
    winrm_transport: str = Form("ntlm"),
    winrm_event_logs: str = Form("System,Application"),
    winrm_batch_size: int = Form(50),
    winrm_use_https: str | None = Form(None),
    winrm_validate_tls: str | None = Form(None),
    ssh_metrics_command: str = Form("cat /proc/loadavg"),
    ssh_log_path: str = Form("/var/log/syslog"),
    ssh_tail_lines: int = Form(50),
    snmp_community: str = Form("public"),
    snmp_version: str = Form("2c"),
    snmp_oids: str = Form("1.3.6.1.2.1.1.3.0,1.3.6.1.2.1.1.5.0"),
    enabled: str | None = Form(None),
) -> RedirectResponse:
    target = CollectorTarget(
        id=target_id.strip(),
        name=name.strip(),
        collector_type=CollectorType(collector_type),
        address=address.strip(),
        port=port,
        username=username.strip(),
        password=password,
        asset_id=asset_id.strip(),
        poll_interval_sec=poll_interval_sec,
        enabled=enabled is not None,
        winrm_transport=winrm_transport.strip() or "ntlm",
        winrm_event_logs=winrm_event_logs.strip() or "System,Application",
        winrm_batch_size=winrm_batch_size,
        winrm_use_https=winrm_use_https is not None,
        winrm_validate_tls=winrm_validate_tls is not None,
        ssh_metrics_command=ssh_metrics_command.strip() or "cat /proc/loadavg",
        ssh_log_path=ssh_log_path.strip() or "/var/log/syslog",
        ssh_tail_lines=ssh_tail_lines,
        snmp_community=snmp_community,
        snmp_version=snmp_version.strip() or "2c",
        snmp_oids=snmp_oids.strip() or "1.3.6.1.2.1.1.3.0,1.3.6.1.2.1.1.5.0",
    )
    service.upsert_collector_target(target)
    return RedirectResponse(url="/ui/collectors", status_code=303)


@app.post("/ui/collectors/{target_id}/delete")
def ui_collectors_delete(target_id: str) -> RedirectResponse:
    service.delete_collector_target(target_id)
    return RedirectResponse(url="/ui/collectors", status_code=303)


@app.get("/ui/assets", response_class=HTMLResponse)
def ui_assets() -> str:
    rows = []
    for asset in service.list_assets():
        rows.append(
            f"<tr><td><a href='/ui/assets/{asset.id}'>{asset.id}</a></td><td>{asset.name}</td>"
            f"<td>{asset.asset_type.value}</td><td>{asset.location or '-'}</td>"
            f"<td><form method='post' action='/ui/assets/{asset.id}/delete' style='margin:0'>"
            f"<button type='submit'>Delete</button></form></td></tr>"
        )
    rows_html = "".join(rows) if rows else "<tr><td colspan='5'>No assets yet</td></tr>"

    return f"""
    <html><body style='font-family: Inter, Arial, sans-serif; max-width: 980px; margin: 2rem auto; background:#f3f5f7; color:#111827;'>
      <h1>Assets</h1>
      <p><a href='/dashboard'>← Dashboard</a> | <a href='/ui/ai'>AI analytics</a></p>
      <form method='post' action='/ui/assets' style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:16px'>
        <label>ID <input name='asset_id' required /></label><br/><br/>
        <label>Name <input name='name' required /></label><br/><br/>
        <label>Type
          <select name='asset_type'>
            <option value='server'>server</option>
            <option value='storage_shelf'>storage_shelf</option>
            <option value='network'>network</option>
            <option value='bmc'>bmc</option>
          </select>
        </label><br/><br/>
        <label>Location <input name='location' /></label><br/><br/>
        <button type='submit'>Save asset</button>
      </form>
      <h2>Registered assets</h2>
      <table border='0' cellpadding='8' cellspacing='0' style='width:100%;background:#fff;border:1px solid #d8dee4;border-radius:10px'>
        <thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Location</th><th>Actions</th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
    </body></html>
    """


@app.post("/ui/assets")
def ui_assets_submit(
    asset_id: str = Form(...),
    name: str = Form(...),
    asset_type: str = Form(...),
    location: str = Form(""),
) -> RedirectResponse:
    asset = Asset(
        id=asset_id.strip(),
        name=name.strip(),
        asset_type=AssetType(asset_type),
        location=location.strip() or None,
    )
    service.upsert_asset(asset)
    return RedirectResponse(url="/ui/assets", status_code=303)


@app.post("/ui/assets/{asset_id}/delete")
def ui_asset_delete(asset_id: str) -> RedirectResponse:
    service.delete_asset(asset_id)
    return RedirectResponse(url="/ui/assets", status_code=303)


@app.get("/ui/assets/{asset_id}", response_class=HTMLResponse)
def ui_asset_detail(asset_id: str) -> str:
    assets = [a for a in service.list_assets() if a.id == asset_id]
    if not assets:
        return "<html><body><h1>Asset not found</h1><a href='/ui/assets'>Back</a></body></html>"

    asset = assets[0]
    events = service.list_events(asset_id, limit=20)
    event_rows = "".join(
        f"<tr><td>{e.timestamp}</td><td>{e.source}</td><td>{e.severity.value}</td><td>{e.message}</td></tr>" for e in events
    ) or "<tr><td colspan='4'>No events yet</td></tr>"

    insights = service.build_correlation_insights(asset_id)
    insights_rows = "".join(
        f"<li><b>{i.title}</b> ({i.confidence}) — {i.recommendation}</li>" for i in insights
    ) or "<li>No insights yet</li>"

    rec = service.build_recommendation(asset_id)
    actions = "".join(f"<li>{a}</li>" for a in rec.actions)

    return f"""
    <html><body style='font-family: Inter, Arial, sans-serif; max-width: 1100px; margin: 2rem auto; background:#f3f5f7; color:#111827;'>
      <h1>Asset detail: {asset.id}</h1>
      <p><a href='/ui/assets'>← Back to assets</a> | <a href='/dashboard'>Dashboard</a> | <a href='/ui/ai?asset_id={asset.id}'>AI analytics</a></p>
      <p><b>Name:</b> {asset.name} | <b>Type:</b> {asset.asset_type.value} | <b>Location:</b> {asset.location or '-'}</p>
      <h2>Recommendation</h2>
      <p><b>Risk score:</b> {rec.risk_score} — {rec.summary}</p>
      <ul>{actions}</ul>
      <h2>Correlation insights</h2>
      <ul>{insights_rows}</ul>
      <h2>Recent events</h2>
      <table border='0' cellpadding='8' cellspacing='0' style='width:100%;background:#fff;border:1px solid #d8dee4;border-radius:10px'>
        <thead><tr><th>Timestamp</th><th>Source</th><th>Severity</th><th>Message</th></tr></thead>
        <tbody>{event_rows}</tbody>
      </table>
    </body></html>
    """




@app.get("/ui/ai", response_class=HTMLResponse)
def ui_ai_analytics(asset_id: str = "", tenant_id: str = "", limit_per_asset: int = 200, max_assets: int = 25) -> str:
    tenant_scope = tenant_id.strip() or None
    requested_asset_id = asset_id.strip()
    tenant_assets = [asset for asset in service.list_assets() if _asset_in_tenant(asset.id, tenant_scope)]
    selected_asset = requested_asset_id or (tenant_assets[0].id if tenant_assets else "")

    rows: list[str] = []
    if selected_asset and any(asset.id == selected_asset for asset in tenant_assets):
        insight = service.build_log_analytics(
            selected_asset,
            limit=min(max(limit_per_asset, 20), 2000),
            max_clusters=10,
            max_anomalies=10,
        )
        for anomaly in insight.anomalies:
            evidence = anomaly.evidence[0] if anomaly.evidence else "-"
            rows.append(
                f"<tr><td>{anomaly.kind}</td><td>{anomaly.severity.value}</td><td>{anomaly.confidence}</td><td>{anomaly.reason}</td><td>{evidence}</td></tr>"
            )

    anomaly_rows = "".join(rows) if rows else "<tr><td colspan='5'>No anomalies for selected asset.</td></tr>"
    options = "".join(
        f"<option value='{asset.id}' {'selected' if asset.id == selected_asset else ''}>{asset.id} ({asset.name})</option>"
        for asset in tenant_assets
    ) or "<option value=''>No assets in scope</option>"

    overview = service.build_log_analytics_overview(
        limit_per_asset=min(max(limit_per_asset, 20), 2000),
        max_assets=min(max(max_assets, 1), 200),
        asset_ids={asset.id for asset in tenant_assets},
    )

    top_assets_rows = "".join(
        f"<tr><td><a href='/ui/ai?asset_id={item.asset_id}{'&tenant_id=' + tenant_scope if tenant_scope else ''}'>{item.asset_id}</a></td><td>{item.anomalies_total}</td><td>{item.top_severity.value if item.top_severity else '-'}</td><td>{item.top_reason or '-'}</td></tr>"
        for item in overview.assets[:10]
    ) or "<tr><td colspan='4'>No analyzed assets.</td></tr>"

    return f"""
    <html><body style='font-family: Inter, Arial, sans-serif; max-width: 1200px; margin: 2rem auto; background:#f3f5f7; color:#111827;'>
      <h1>AI analytics center</h1>
      <p><a href='/dashboard'>← Dashboard</a> | <a href='/ui/assets'>Assets</a> | <a href='/ui/ai/policies'>AI Policy Center</a> | <a href='/ai-log-analytics/overview'>JSON API overview</a></p>
      <form method='get' action='/ui/ai' style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:16px;margin-bottom:14px'>
        <label>Asset
          <select name='asset_id'>{options}</select>
        </label>
        <label style='margin-left:10px'>Tenant id <input name='tenant_id' value='{tenant_scope or ''}' placeholder='optional'/></label>
        <button type='submit'>Load analytics</button>
      </form>

      <div style='display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px'>
        <div style='background:#fff;border:1px solid #d8dee4;border-radius:10px;padding:12px'><b>Assets considered</b><div style='font-size:30px'>{overview.assets_considered}</div></div>
        <div style='background:#fff;border:1px solid #d8dee4;border-radius:10px;padding:12px'><b>Assets with anomalies</b><div style='font-size:30px'>{overview.assets_with_anomalies}</div></div>
        <div style='background:#fff;border:1px solid #d8dee4;border-radius:10px;padding:12px'><b>Total anomalies</b><div style='font-size:30px'>{overview.total_anomalies}</div></div>
      </div>

      <h2>Top assets by anomalies</h2>
      <table border='0' cellpadding='8' cellspacing='0' style='width:100%;background:#fff;border:1px solid #d8dee4;border-radius:10px'>
        <thead><tr><th>Asset</th><th>Anomalies</th><th>Top severity</th><th>Top reason</th></tr></thead>
        <tbody>{top_assets_rows}</tbody>
      </table>

      <h2>Selected asset anomalies</h2>
      <table border='0' cellpadding='8' cellspacing='0' style='width:100%;background:#fff;border:1px solid #d8dee4;border-radius:10px'>
        <thead><tr><th>Kind</th><th>Severity</th><th>Confidence</th><th>Reason</th><th>Evidence</th></tr></thead>
        <tbody>{anomaly_rows}</tbody>
      </table>
    </body></html>
    """



def _policy_snapshot_dict(policy: LogAnalyticsPolicy | None) -> dict[str, object] | None:
    if policy is None:
        return None
    return {
        "id": policy.id,
        "name": policy.name,
        "tenant_id": policy.tenant_id,
        "enabled": policy.enabled,
        "ignore_sources": sorted(policy.ignore_sources),
        "ignore_signatures": sorted(policy.ignore_signatures),
    }


def _build_policy_audit_details(action: str, before: LogAnalyticsPolicy | None, after: LogAnalyticsPolicy | None = None) -> str:
    before_snapshot = _policy_snapshot_dict(before)
    after_snapshot = _policy_snapshot_dict(after)
    changed_fields: list[str] = []
    if action == "delete":
        changed_fields = ["deleted"]
    elif before_snapshot is None and after_snapshot is not None:
        changed_fields = ["created", "name", "tenant_id", "enabled", "ignore_sources", "ignore_signatures"]
    elif before_snapshot is not None and after_snapshot is not None:
        for key in ("name", "tenant_id", "enabled", "ignore_sources", "ignore_signatures"):
            if before_snapshot.get(key) != after_snapshot.get(key):
                changed_fields.append(key)

    payload: dict[str, object] = {
        "schema_version": 1,
        "action": action,
        "changed_fields": changed_fields,
        "before": before_snapshot,
    }
    if after_snapshot is not None:
        payload["after"] = after_snapshot
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _parse_policy_audit_details(details: str) -> LogAnalyticsPolicyAuditDetails | None:
    try:
        payload = json.loads(details)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    try:
        return LogAnalyticsPolicyAuditDetails(**payload)
    except Exception:
        return None


def _render_audit_nav_link(label: str, href: str, enabled: bool, disabled_hint: str, margin_left: str = "10px") -> str:
    if enabled:
        return f"<a href='{href}' style='margin-left:{margin_left}'>{label}</a>"
    return f"<span style='margin-left:{margin_left};color:#94a3b8' title='{disabled_hint}'>{label}</span>"


@app.get("/ui/ai/policies", response_class=HTMLResponse)
def ui_ai_policy_center(
    tenant_id: str = "",
    policy_id: str = "",
    asset_id: str = "",
    merge_strategy: PolicyMergeStrategy = PolicyMergeStrategy.union,
    audit_action: str = "",
    audit_policy_id: str = "",
    audit_min_ts: str = "",
    audit_max_ts: str = "",
    audit_sort: str = "desc",
    audit_offset: int = 0,
    audit_limit: int = 20,
    audit_page: int = 1,
    audit_changed_field: str = "",
    impact_mode: str = "weighted",
) -> str:
    tenant_scope = tenant_id.strip() or None
    selected_policy_id = policy_id.strip()
    selected_asset_id = asset_id.strip()

    policies = service.list_ai_log_policies(tenant_id=tenant_scope)
    policy_rows = "".join(
        f"<tr><td>{item.id}</td><td>{item.name}</td><td>{item.tenant_id or '-'}</td><td>{'on' if item.enabled else 'off'}</td><td>{len(item.ignore_sources)}</td><td>{len(item.ignore_signatures)}</td><td><form method='post' action='/ui/ai/policies/{item.id}/delete' style='margin:0'><input type='hidden' name='tenant_id' value='{tenant_scope or ''}'/><button type='submit'>Delete</button></form></td></tr>"
        for item in policies
    ) or "<tr><td colspan='7'>No policies yet.</td></tr>"

    audit_action_norm = audit_action.strip() or None
    audit_policy_id_norm = audit_policy_id.strip() or None
    audit_min_ts_norm = int(audit_min_ts.strip()) if audit_min_ts.strip().isdigit() else None
    audit_max_ts_norm = int(audit_max_ts.strip()) if audit_max_ts.strip().isdigit() else None
    audit_sort_norm = audit_sort.strip().lower()
    audit_changed_field_norm = audit_changed_field.strip() or None
    if audit_sort_norm not in {"asc", "desc"}:
        audit_sort_norm = "desc"

    limit_norm = min(max(audit_limit, 1), 200)
    page_norm = max(1, audit_page)
    offset_norm = max(0, audit_offset)
    if page_norm > 1:
        offset_norm = (page_norm - 1) * limit_norm

    audit_rows = service.list_ai_log_policy_audit(
        limit=limit_norm,
        tenant_id=tenant_scope,
        action=audit_action_norm,
        policy_id=audit_policy_id_norm,
        min_ts=audit_min_ts_norm,
        max_ts=audit_max_ts_norm,
        sort=audit_sort_norm,
        offset=offset_norm,
        changed_field=audit_changed_field_norm,
    )
    total_audit_rows = service.count_ai_log_policy_audit(
        tenant_id=tenant_scope,
        action=audit_action_norm,
        policy_id=audit_policy_id_norm,
        min_ts=audit_min_ts_norm,
        max_ts=audit_max_ts_norm,
        changed_field=audit_changed_field_norm,
    )
    audit_html = "".join(
        f"<tr><td>{row.ts}</td><td><a href='/ui/ai/policies?tenant_id={tenant_scope or ''}&audit_policy_id={row.policy_id}'>{row.policy_id}</a></td><td>{row.action}</td><td>{row.actor_role}</td><td>{row.details}</td></tr>"
        for row in audit_rows
    ) or "<tr><td colspan='5'>No audit rows.</td></tr>"

    audit_csv_params = [
        f"tenant_id={tenant_scope}" if tenant_scope else "",
        f"action={audit_action_norm}" if audit_action_norm else "",
        f"policy_id={audit_policy_id_norm}" if audit_policy_id_norm else "",
        f"min_ts={audit_min_ts_norm}" if audit_min_ts_norm is not None else "",
        f"max_ts={audit_max_ts_norm}" if audit_max_ts_norm is not None else "",
        f"sort={audit_sort_norm}",
        f"offset={offset_norm}",
        f"limit={limit_norm}",
    ]
    audit_csv_query = "&".join(item for item in audit_csv_params if item)

    impact_mode_norm = impact_mode.strip().lower() or "weighted"
    if impact_mode_norm not in {"weighted", "critical_warning", "critical_only"}:
        impact_mode_norm = "weighted"

    ui_filter_params = [
        f"tenant_id={tenant_scope}" if tenant_scope else "",
        f"policy_id={selected_policy_id}" if selected_policy_id else "",
        f"asset_id={selected_asset_id}" if selected_asset_id else "",
        f"merge_strategy={merge_strategy.value if isinstance(merge_strategy, PolicyMergeStrategy) else str(merge_strategy)}",
        f"impact_mode={impact_mode_norm}",
        f"audit_action={audit_action_norm}" if audit_action_norm else "",
        f"audit_policy_id={audit_policy_id_norm}" if audit_policy_id_norm else "",
        f"audit_min_ts={audit_min_ts_norm}" if audit_min_ts_norm is not None else "",
        f"audit_max_ts={audit_max_ts_norm}" if audit_max_ts_norm is not None else "",
        f"audit_sort={audit_sort_norm}",
        f"audit_changed_field={audit_changed_field_norm}" if audit_changed_field_norm else "",
        f"changed_field={audit_changed_field_norm}" if audit_changed_field_norm else "",
        f"audit_limit={limit_norm}",
    ]
    ui_filter_query_base = "&".join(item for item in ui_filter_params if item)
    prev_offset = max(0, offset_norm - limit_norm)
    next_offset = offset_norm + limit_norm
    current_page = (offset_norm // limit_norm) + 1
    page_start = max(1, current_page - 2)
    page_end = page_start + 4
    page_links = []
    for page in range(page_start, page_end + 1):
        page_offset = (page - 1) * limit_norm
        if page == current_page:
            page_links.append(f"<span style='color:#0f172a;font-weight:700'>{page}</span>")
        else:
            page_links.append(f"<a href='/ui/ai/policies?{ui_filter_query_base}&audit_offset={page_offset}'>{page}</a>")
    page_links_html = " | ".join(page_links)
    last_page = max(1, (total_audit_rows + limit_norm - 1) // limit_norm)
    last_offset = max(0, (last_page - 1) * limit_norm)

    first_link = _render_audit_nav_link(
        label='⏮ First',
        href=f'/ui/ai/policies?{ui_filter_query_base}&audit_offset=0',
        enabled=current_page > 1,
        disabled_hint='Already at first page',
    )
    prev_link = _render_audit_nav_link(
        label='◀ Prev',
        href=f'/ui/ai/policies?{ui_filter_query_base}&audit_offset={prev_offset}',
        enabled=current_page > 1,
        disabled_hint='Already at first page',
    )
    next_link = _render_audit_nav_link(
        label='Next ▶',
        href=f'/ui/ai/policies?{ui_filter_query_base}&audit_offset={next_offset}',
        enabled=current_page < last_page,
        disabled_hint='Already at last page',
    )
    jump_link = _render_audit_nav_link(
        label='Jump +5 pages',
        href=f'/ui/ai/policies?{ui_filter_query_base}&audit_page={max(current_page + 5, 1)}',
        enabled=current_page < last_page,
        disabled_hint='Already at last page',
    )
    last_link = _render_audit_nav_link(
        label='⏭ Last',
        href=f'/ui/ai/policies?{ui_filter_query_base}&audit_offset={last_offset}',
        enabled=current_page < last_page,
        disabled_hint='Already at last page',
    )

    api_url = f"/ai-log-analytics/policies/audit?{audit_csv_query}"

    dry_run_html = ""
    if selected_policy_id and selected_asset_id:
        try:
            dry_run = service.preview_ai_log_policy_effect(
                asset_id=selected_asset_id,
                policy_id=selected_policy_id,
                merge_strategy=merge_strategy,
                tenant_id=tenant_scope,
                impact_mode=impact_mode_norm,
            )
            impact_rows = "".join(
                f"<tr><td>{item.cluster_id}</td><td>{item.source}</td><td>{item.events_filtered}</td><td>{item.severity_mix}</td><td>{item.impact_score}</td><td>{item.signature}</td></tr>"
                for item in dry_run.top_impacted_clusters
            ) or "<tr><td colspan='6'>No impacted clusters.</td></tr>"
            dry_run_html = (
                f"<div style='background:#fff;border:1px solid #d8dee4;border-radius:10px;padding:12px;margin:10px 0'>"
                f"<b>Dry-run result:</b> total={dry_run.total_events}, filtered={dry_run.filtered_events} ({int(dry_run.filtered_share*100)}%), remaining={dry_run.remaining_events} ({int(dry_run.remaining_share*100)}%)"
                f"<br/><span style='font-size:12px;color:#64748b'>mode={dry_run.impact_mode} | sources={', '.join(dry_run.applied_sources) or '-'} | signatures={len(dry_run.applied_signatures)}</span>"
                f"<div style='margin-top:10px'><b>Top impacted clusters</b></div>"
                f"<table border='0' cellpadding='6' cellspacing='0' style='width:100%;margin-top:6px;background:#fff;border:1px solid #e2e8f0'>"
                f"<thead><tr><th>Cluster</th><th>Source</th><th>Filtered events</th><th>Severity mix</th><th>Impact score</th><th>Signature</th></tr></thead><tbody>{impact_rows}</tbody></table>"
                f"</div>"
            )
        except KeyError as exc:
            dry_run_html = f"<div style='color:#b91c1c;margin:10px 0'>Dry-run failed: {exc}</div>"

    asset_options = "".join(
        f"<option value='{asset.id}' {'selected' if asset.id == selected_asset_id else ''}>{asset.id}</option>"
        for asset in service.list_assets()
        if _asset_in_tenant(asset.id, tenant_scope)
    ) or "<option value=''>No assets in scope</option>"
    policy_options = "".join(
        f"<option value='{item.id}' {'selected' if item.id == selected_policy_id else ''}>{item.id} ({item.name})</option>"
        for item in policies
    ) or "<option value=''>No policies</option>"

    return f"""
    <html><body style='font-family: Inter, Arial, sans-serif; max-width: 1200px; margin: 2rem auto; background:#f3f5f7; color:#111827;'>
      <h1>AI policy center</h1>
      <p><a href='/ui/ai'>← AI analytics</a> | <a href='/dashboard'>Dashboard</a> | <a href='/ai-log-analytics/policies'>JSON policies API</a></p>

      <form method='post' action='/ui/ai/policies' style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:16px'>
        <h3>Create/update policy</h3>
        <label>ID <input name='policy_id' required/></label>
        <label style='margin-left:10px'>Name <input name='name' required/></label>
        <label style='margin-left:10px'>Tenant <input name='tenant_id' value='{tenant_scope or ''}' placeholder='optional'/></label><br/><br/>
        <label>Ignore sources (csv) <input name='ignore_sources' style='min-width:420px'/></label><br/><br/>
        <label>Ignore signatures (csv) <input name='ignore_signatures' style='min-width:420px'/></label><br/><br/>
        <label><input type='checkbox' name='enabled' checked/> enabled</label><br/><br/>
        <button type='submit'>Save policy</button>
      </form>

      <h3 style='margin-top:16px'>Policies</h3>
      <table border='0' cellpadding='8' cellspacing='0' style='width:100%;background:#fff;border:1px solid #d8dee4;border-radius:10px'>
        <thead><tr><th>ID</th><th>Name</th><th>Tenant</th><th>Enabled</th><th>Ignore sources</th><th>Ignore signatures</th><th>Actions</th></tr></thead>
        <tbody>{policy_rows}</tbody>
      </table>

      <h3 style='margin-top:16px'>Policy dry-run</h3>
      <form method='get' action='/ui/ai/policies' style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:16px'>
        <input type='hidden' name='tenant_id' value='{tenant_scope or ''}'/>
        <label>Policy <select name='policy_id'>{policy_options}</select></label>
        <label style='margin-left:10px'>Asset <select name='asset_id'>{asset_options}</select></label>
        <label style='margin-left:10px'>Merge
          <select name='merge_strategy'>
            <option value='union' {'selected' if merge_strategy == PolicyMergeStrategy.union else ''}>union</option>
            <option value='intersection' {'selected' if merge_strategy == PolicyMergeStrategy.intersection else ''}>intersection</option>
          </select>
        </label>
        <label style='margin-left:10px'>Impact mode
          <select name='impact_mode'>
            <option value='weighted' {'selected' if impact_mode_norm == 'weighted' else ''}>weighted</option>
            <option value='critical_warning' {'selected' if impact_mode_norm == 'critical_warning' else ''}>critical_warning</option>
            <option value='critical_only' {'selected' if impact_mode_norm == 'critical_only' else ''}>critical_only</option>
          </select>
        </label>
        <button type='submit'>Run dry-run</button>
      </form>
      {dry_run_html}

      <h3>Recent policy audit</h3>
      <form method='get' action='/ui/ai/policies' style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:16px;margin-bottom:10px'>
        <input type='hidden' name='tenant_id' value='{tenant_scope or ''}'/>
        <label>Action <input name='audit_action' value='{audit_action_norm or ''}' placeholder='upsert/delete'/></label>
        <label style='margin-left:10px'>Policy <input name='audit_policy_id' value='{audit_policy_id_norm or ''}'/></label>
        <label style='margin-left:10px'>Min ts <input name='audit_min_ts' value='{audit_min_ts_norm or ''}'/></label>
        <label style='margin-left:10px'>Max ts <input name='audit_max_ts' value='{audit_max_ts_norm or ''}'/></label>
        <label style='margin-left:10px'>Changed field <input name='audit_changed_field' value='{audit_changed_field_norm or ''}' placeholder='enabled|ignore_sources|deleted'/></label>
        <a href='/ui/ai/policies?{ui_filter_query_base}&audit_changed_field=enabled' style='margin-left:8px;font-size:12px'>preset: enabled</a>
        <a href='/ui/ai/policies?{ui_filter_query_base}&audit_changed_field=ignore_sources' style='margin-left:6px;font-size:12px'>preset: ignore_sources</a>
        <a href='/ui/ai/policies?{ui_filter_query_base}&audit_changed_field=deleted' style='margin-left:6px;font-size:12px'>preset: deleted</a>
        <label style='margin-left:10px'>Sort
          <select name='audit_sort'>
            <option value='desc' {'selected' if audit_sort_norm == 'desc' else ''}>desc</option>
            <option value='asc' {'selected' if audit_sort_norm == 'asc' else ''}>asc</option>
          </select>
        </label>
        <label style='margin-left:10px'>Offset <input name='audit_offset' type='number' min='0' value='{offset_norm}'/></label>
        <label style='margin-left:10px'>Page <input name='audit_page' type='number' min='1' value='{current_page}'/></label>
        <label style='margin-left:10px'>Limit <input name='audit_limit' type='number' min='1' max='200' value='{limit_norm}'/></label>
        <button type='submit'>Apply audit filters</button>
        <a href='/ai-log-analytics/policies/audit?{audit_csv_query}' style='margin-left:10px'>Open JSON</a>
        <a href='/ai-log-analytics/policies/audit.csv?{audit_csv_query}' style='margin-left:10px'>Export CSV</a>
        {first_link}
        {prev_link}
        {next_link}
        {jump_link}
        {last_link}
      </form>
      <div style='margin:6px 0 12px;font-size:13px;color:#334155'>Pages: {page_links_html} &nbsp;|&nbsp; total rows: {total_audit_rows}</div>
      <div style='margin:0 0 10px'>
        <label style='font-size:12px;color:#64748b'>API URL for current filters</label><br/>
        <input id='api-url-current' readonly value='{api_url}' style='width:100%;max-width:980px'/>
        <button type='button' style='margin-left:6px' onclick="copyPolicyAuditUrl(document.getElementById('api-url-current').value)">Copy API URL</button>
        <button type='button' style='margin-left:6px' onclick="copyPolicyAuditUrl('/ai-log-analytics/policies/audit?{audit_csv_query}')">Copy JSON URL</button>
        <button type='button' style='margin-left:6px' onclick="copyPolicyAuditUrl('/ai-log-analytics/policies/audit.csv?{audit_csv_query}')">Copy CSV URL</button>
        <span id='copy-status' style='margin-left:8px;font-size:12px;color:#16a34a'></span>
      </div>
      <script>
        function copyPolicyAuditUrl(value) {{
          navigator.clipboard.writeText(value);
          const status = document.getElementById('copy-status');
          if (status) {{
            status.textContent = 'copied';
            setTimeout(() => {{ status.textContent = ''; }}, 1200);
          }}
        }}
      </script>
      <table border='0' cellpadding='8' cellspacing='0' style='width:100%;background:#fff;border:1px solid #d8dee4;border-radius:10px'>
        <thead><tr><th>TS</th><th>Policy</th><th>Action</th><th>Actor role</th><th>Details</th></tr></thead>
        <tbody>{audit_html}</tbody>
      </table>
    </body></html>
    """


@app.post("/ui/ai/policies")
def ui_ai_policy_center_upsert(
    policy_id: str = Form(...),
    name: str = Form(...),
    tenant_id: str = Form(""),
    ignore_sources: str = Form(""),
    ignore_signatures: str = Form(""),
    enabled: str | None = Form(None),
) -> RedirectResponse:
    tenant_scope = tenant_id.strip() or None
    policy = LogAnalyticsPolicy(
        id=policy_id.strip(),
        name=name.strip(),
        tenant_id=tenant_scope,
        ignore_sources=[item.strip().lower() for item in ignore_sources.split(",") if item.strip()],
        ignore_signatures=[item.strip().lower() for item in ignore_signatures.split(",") if item.strip()],
        enabled=enabled is not None,
    )
    before = service.storage.get_ai_log_policy(policy.id, tenant_id=tenant_scope)
    stored = service.upsert_ai_log_policy(policy)
    service.add_ai_log_policy_audit(
        LogAnalyticsPolicyAuditEntry(
            ts=int(time.time()),
            policy_id=stored.id,
            tenant_id=stored.tenant_id,
            action="upsert",
            actor_role="ui",
            details=_build_policy_audit_details("upsert", before=before, after=stored),
        )
    )
    tenant_q = f"?tenant_id={tenant_scope}" if tenant_scope else ""
    return RedirectResponse(url=f"/ui/ai/policies{tenant_q}", status_code=303)


@app.post("/ui/ai/policies/{policy_id}/delete")
def ui_ai_policy_center_delete(policy_id: str, tenant_id: str = Form("")) -> RedirectResponse:
    tenant_scope = tenant_id.strip() or None
    try:
        before = service.storage.get_ai_log_policy(policy_id.strip(), tenant_id=tenant_scope)
        service.delete_ai_log_policy(policy_id.strip(), tenant_id=tenant_scope)
        service.add_ai_log_policy_audit(
            LogAnalyticsPolicyAuditEntry(
                ts=int(time.time()),
                policy_id=policy_id.strip(),
                tenant_id=tenant_scope,
                action="delete",
                actor_role="ui",
                details=_build_policy_audit_details("delete", before=before),
            )
        )
    except KeyError:
        pass

    tenant_q = f"?tenant_id={tenant_scope}" if tenant_scope else ""
    return RedirectResponse(url=f"/ui/ai/policies{tenant_q}", status_code=303)

@app.get("/ui/events", response_class=HTMLResponse)
def ui_events() -> str:
    options = "".join(f"<option value='{a.id}'>{a.id} ({a.name})</option>" for a in service.list_assets())
    if not options:
        options = "<option value=''>No assets. Create one first.</option>"

    return f"""
    <html><body style='font-family: Inter, Arial, sans-serif; max-width: 980px; margin: 2rem auto; background:#f3f5f7; color:#111827;'>
      <h1>Add Event</h1>
      <p><a href='/dashboard'>← Dashboard</a> | <a href='/ui/assets'>Manage assets</a></p>
      <form method='post' action='/ui/events' style='background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:16px'>
        <label>Asset
          <select name='asset_id' required>{options}</select>
        </label><br/><br/>
        <label>Source <input name='source' value='manual_ui' required /></label><br/><br/>
        <label>Message <input name='message' required style='min-width:420px'/></label><br/><br/>
        <label>Metric <input name='metric' placeholder='optional'/></label><br/><br/>
        <label>Value <input name='value' type='number' step='0.01' placeholder='optional'/></label><br/><br/>
        <label>Severity
          <select name='severity'>
            <option value='info'>info</option>
            <option value='warning'>warning</option>
            <option value='critical'>critical</option>
          </select>
        </label><br/><br/>
        <button type='submit'>Send event</button>
      </form>
    </body></html>
    """


@app.post("/ui/events")
def ui_events_submit(
    asset_id: str = Form(...),
    source: str = Form(...),
    message: str = Form(...),
    metric: str = Form(""),
    value: str = Form(""),
    severity: str = Form("info"),
) -> RedirectResponse:
    event = Event(
        asset_id=asset_id.strip(),
        source=source.strip(),
        message=message.strip(),
        metric=metric.strip() or None,
        value=float(value) if value.strip() else None,
        severity=Severity(severity),
    )
    service.register_event(event)
    return RedirectResponse(url=f"/ui/assets/{asset_id}", status_code=303)


def _worker_health_snapshot() -> dict[str, int | str | bool]:
    status = worker.status()
    targets = worker.target_status()
    failed = sum(1 for t in targets if not t.get("last_ok", False) and t.get("last_run_ts") is not None)
    stale = sum(1 for t in targets if t.get("last_run_ts") is None)
    return {
        "running": status.get("running", False),
        "enabled": ENABLE_AGENTLESS_WORKER,
        "tracked": len(targets),
        "failed": failed,
        "stale": stale,
        "cycle_count": int(status.get("cycle_count", 0)),
    }


def _parse_has_error_filter(has_error: str | None) -> bool | None:
    if has_error == "1":
        return True
    if has_error == "0":
        return False
    return None




def _normalize_tenant_id(value: str | None) -> str | None:
    if not value:
        return None
    v = str(value).strip()
    if not v:
        return None
    return v


def _resolve_tenant_scope(request: Request, tenant_hint: str | None = None) -> str | None:
    header_tenant = _normalize_tenant_id(request.headers.get(AUTH_TENANT_HEADER_NAME, ""))
    if header_tenant:
        return header_tenant
    return _normalize_tenant_id(tenant_hint)


def _asset_in_tenant(asset_id: str, tenant_id: str | None) -> bool:
    if not tenant_id:
        return True
    return asset_id.startswith(f"{tenant_id}:")


def _tenant_target_ids(tenant_id: str | None) -> set[str]:
    if not tenant_id:
        return set()
    ids = set()
    for t in service.list_collector_targets():
        if _asset_in_tenant(t.asset_id, tenant_id):
            ids.add(t.id)
    return ids


def _filter_history_by_tenant(rows: list[dict], tenant_id: str | None) -> list[dict]:
    if not tenant_id:
        return rows
    allowed = _tenant_target_ids(tenant_id)
    return [r for r in rows if str(r.get("target_id", "")) in allowed]


def _normalize_role(role: str | None) -> str:
    if role in {"viewer", "operator", "admin"}:
        return str(role)
    return "viewer"


def _can_view_worker_history(role: str) -> bool:
    return role in {"operator", "admin"}


def _can_control_worker(role: str) -> bool:
    return role in {"operator", "admin"}


def _resolve_auth_context_from_request(
    request: Request,
    role_hint: str | None,
    default_role: str,
) -> AuthContext:
    authz = request.headers.get("Authorization", "").strip()
    if authz.lower().startswith("bearer "):
        token = authz.split(" ", 1)[1].strip()
        jwt_rs_role = _parse_jwt_rs256_role(token)
        if jwt_rs_role:
            return AuthContext(role=jwt_rs_role, source="jwt_rs256", tenant_id=_resolve_tenant_scope(request, tenant_hint=None))
        jwt_role = _parse_jwt_hs256_role(token)
        if jwt_role:
            return AuthContext(role=jwt_role, source="jwt_hs256", tenant_id=_resolve_tenant_scope(request, tenant_hint=None))
        parsed_role = _parse_bearer_token(token)
        if parsed_role:
            return AuthContext(role=parsed_role, source="bearer_signed", tenant_id=_resolve_tenant_scope(request, tenant_hint=None))
        if token in AUTH_TOKEN_ROLE_MAP:
            return AuthContext(role=_normalize_role(AUTH_TOKEN_ROLE_MAP[token]), source="bearer_static", tenant_id=_resolve_tenant_scope(request, tenant_hint=None))

    token = request.headers.get("X-Auth-Token", "").strip()
    if token and token in AUTH_TOKEN_ROLE_MAP:
        return AuthContext(role=_normalize_role(AUTH_TOKEN_ROLE_MAP[token]), source="header_token", tenant_id=_resolve_tenant_scope(request, tenant_hint=None))

    header_role = request.headers.get("X-Role", "").strip()
    if header_role:
        return AuthContext(role=_normalize_role(header_role), source="header_role", tenant_id=_resolve_tenant_scope(request, tenant_hint=None))

    session_role = _parse_session_value(request.cookies.get(SESSION_COOKIE_NAME))
    if session_role:
        return AuthContext(role=session_role, source="session", tenant_id=_resolve_tenant_scope(request, tenant_hint=None))

    if ALLOW_QUERY_ROLE and role_hint:
        return AuthContext(role=_normalize_role(role_hint), source="query_role", tenant_id=_resolve_tenant_scope(request, tenant_hint=None))

    return AuthContext(role=_normalize_role(default_role), source="default", tenant_id=_resolve_tenant_scope(request, tenant_hint=None))


def _resolve_role_from_request(
    request: Request,
    role_hint: str | None,
    default_role: str,
) -> str:
    return _resolve_auth_context_from_request(request, role_hint, default_role).role


ROLE_ORDER = {"viewer": 0, "operator": 1, "admin": 2}


def _append_access_audit(entry: dict[str, str | int]) -> None:
    service.add_access_audit(
        AccessAuditEntry(
            ts=int(entry.get("ts", int(time.time()))),
            path=str(entry.get("path", "")),
            role=str(entry.get("role", "viewer")),
            action=str(entry.get("action", "")),
            result=str(entry.get("result", "allow")),
        )
    )


def _build_compliance_summary(limit: int = 1000) -> dict[str, object]:
    rows = service.list_access_audit(limit=max(1, min(limit, 5000)))
    by_result = Counter(a.result for a in rows)
    by_role = Counter(a.role for a in rows)
    return {
        "rows": len(rows),
        "allow": by_result.get("allow", 0),
        "deny": by_result.get("deny", 0),
        "by_role": dict(by_role),
        "jwt_rejects": dict(JWT_REJECT_TELEMETRY),
    }


def _route_compliance_report(report_id: str) -> None:
    ts = int(time.time())
    routes = [
        ("webhook", COMPLIANCE_WEBHOOK_URL.strip()),
        ("email", COMPLIANCE_EMAIL_TO.strip()),
    ]
    if not any(dest for _, dest in routes):
        COMPLIANCE_REPORT_DELIVERIES.appendleft(
            {"ts": ts, "report_id": report_id, "channel": "none", "destination": "", "status": "skipped"}
        )
        return

    for channel, destination in routes:
        if not destination:
            continue
        COMPLIANCE_REPORT_DELIVERIES.appendleft(
            {"ts": ts, "report_id": report_id, "channel": channel, "destination": destination, "status": "configured"}
        )


def _generate_compliance_report(trigger: str = "manual") -> dict[str, object]:
    global COMPLIANCE_LAST_REPORT_TS
    now = int(time.time())
    report = {
        "id": f"cr-{now}",
        "ts": now,
        "trigger": trigger,
        "summary": _build_compliance_summary(limit=2000),
    }
    COMPLIANCE_REPORTS.appendleft(report)
    COMPLIANCE_LAST_REPORT_TS = now
    _route_compliance_report(report["id"])
    return report


def _ensure_scheduled_compliance_report() -> None:
    if COMPLIANCE_REPORT_INTERVAL_SEC <= 0:
        return
    now = int(time.time())
    if now - int(COMPLIANCE_LAST_REPORT_TS) >= COMPLIANCE_REPORT_INTERVAL_SEC:
        _generate_compliance_report(trigger="scheduled")


def _require_role(
    request: Request,
    role_hint: str | None,
    minimum_role: str,
    action: str,
    default_role: str = "viewer",
) -> str:
    role_value = _resolve_role_from_request(request, role_hint, default_role=default_role)
    if ROLE_ORDER[role_value] < ROLE_ORDER[minimum_role]:
        _append_access_audit(
            {
                "ts": int(time.time()),
                "path": request.url.path,
                "role": role_value,
                "action": action,
                "result": "deny",
            }
        )
        raise HTTPException(status_code=403, detail=f"Role '{role_value}' is not allowed to {action}")
    _append_access_audit(
        {
            "ts": int(time.time()),
            "path": request.url.path,
            "role": role_value,
            "action": action,
            "result": "allow",
        }
    )
    return role_value


def _require_operator_dependency(request: Request, role: str | None = None) -> str:
    return _require_role(request, role, minimum_role="operator", action="operator action", default_role="admin")


def _require_admin_dependency(request: Request, role: str | None = None) -> str:
    return _require_role(request, role, minimum_role="admin", action="admin action", default_role="viewer")


def _require_role_dependency(minimum_role: str, action: str, default_role: str = "viewer"):
    def _dependency(request: Request, role: str | None = None) -> str:
        return _require_role(request, role, minimum_role=minimum_role, action=action, default_role=default_role)

    return _dependency


require_worker_history_read = _require_role_dependency("operator", "read worker history", default_role="admin")
require_worker_history_export = _require_role_dependency("operator", "export worker history", default_role="admin")


@app.get("/auth/whoami")
def auth_whoami(request: Request, role: str | None = None) -> dict[str, str | bool]:
    context = _resolve_auth_context_from_request(request, role, default_role="viewer") if role else getattr(request.state, "auth_context", _resolve_auth_context_from_request(request, None, default_role="viewer"))
    return {
        "role": context.role,
        "source": context.source,
        "has_token": bool(request.headers.get("X-Auth-Token", "").strip() or request.headers.get("Authorization", "")),
        "has_session": bool(_parse_session_value(request.cookies.get(SESSION_COOKIE_NAME))),
        "used_query_role_hint": bool(role),
        "allow_query_role": ALLOW_QUERY_ROLE,
        "jwt_hs256_enabled": bool(AUTH_JWT_HS256_SECRET),
        "jwt_jwks_enabled": bool(_resolve_jwks_url()),
        "oidc_discovery_enabled": bool(AUTH_OIDC_DISCOVERY_URL),
        "issuer_role_profiles": len(ISSUER_ROLE_CLAIM_MAP),
    }


@app.post("/auth/login")
def auth_login(username: str = Form(...), password: str = Form(...)) -> JSONResponse:
    record = AUTH_USER_MAP.get(username.strip())
    if not record or record[0] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    role = _normalize_role(record[1])
    response = JSONResponse({"status": "ok", "role": role})
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=_create_session_value(role),
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL_SEC,
    )
    return response


@app.post("/auth/token")
def auth_token(username: str = Form(...), password: str = Form(...)) -> dict[str, str | int]:
    record = AUTH_USER_MAP.get(username.strip())
    if not record or record[0] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    role = _normalize_role(record[1])
    return {"access_token": _create_bearer_token(role), "token_type": "bearer", "expires_in": TOKEN_TTL_SEC, "role": role}


@app.post("/auth/logout")
def auth_logout() -> JSONResponse:
    response = JSONResponse({"status": "ok"})
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@app.get("/auth/audit")
def auth_audit(request: Request, limit: int = 100, _role: str = Depends(_require_admin_dependency)) -> list[dict[str, str | int]]:
    return [a.model_dump() for a in service.list_access_audit(limit=max(1, min(limit, 500)))]


@app.get("/auth/audit.csv", response_class=PlainTextResponse)
def auth_audit_csv(request: Request, limit: int = 1000, _role: str = Depends(_require_admin_dependency)) -> str:
    rows = service.list_access_audit(limit=max(1, min(limit, 5000)))
    header = "ts,path,role,action,result"

    def esc(v: str) -> str:
        return '"' + v.replace('"', '""') + '"'

    lines = [header]
    for a in rows:
        lines.append(",".join([str(a.ts), esc(a.path), esc(a.role), esc(a.action), esc(a.result)]))
    return "\n".join(lines)


@app.get("/auth/audit/summary")
def auth_audit_summary(request: Request, limit: int = 1000, _role: str = Depends(_require_admin_dependency)) -> dict:
    rows = service.list_access_audit(limit=max(1, min(limit, 5000)))
    by_result = Counter(a.result for a in rows)
    by_role = Counter(a.role for a in rows)
    by_action = Counter(a.action for a in rows)
    return {
        "rows": len(rows),
        "allow": by_result.get("allow", 0),
        "deny": by_result.get("deny", 0),
        "by_role": dict(by_role),
        "top_actions": [{"action": k, "count": v} for k, v in by_action.most_common(10)],
    }


@app.get("/auth/audit/alerts")
def auth_audit_alerts(request: Request, lookback: int = 200, deny_threshold: int = 20, _role: str = Depends(_require_admin_dependency)) -> dict:
    rows = service.list_access_audit(limit=max(1, min(lookback, 5000)))
    denies = [a for a in rows if a.result == "deny"]
    alerts = []
    if len(denies) >= max(1, deny_threshold):
        alerts.append({"kind": "high_deny_rate", "deny": len(denies), "lookback": lookback, "threshold": deny_threshold})
    return {"alerts": alerts, "deny": len(denies), "lookback": lookback}


@app.get("/auth/jwt/reject-telemetry")
def auth_jwt_reject_telemetry(request: Request, _role: str = Depends(_require_admin_dependency)) -> dict:
    return {"counters": dict(JWT_REJECT_TELEMETRY), "by_issuer_client": dict(JWT_REJECT_BY_ISSUER_CLIENT)}


@app.get("/auth/jwt/reject-telemetry/details")
def auth_jwt_reject_telemetry_details(request: Request, limit: int = 100, _role: str = Depends(_require_admin_dependency)) -> list[dict[str, str | int]]:
    n = max(1, min(limit, 500))
    return list(JWT_REJECT_EVENTS)[:n]


@app.get("/auth/compliance/status")
def auth_compliance_status(request: Request, _role: str = Depends(_require_admin_dependency)) -> dict[str, object]:
    return {
        "report_interval_sec": COMPLIANCE_REPORT_INTERVAL_SEC,
        "report_retention": COMPLIANCE_REPORT_RETENTION,
        "reports": len(COMPLIANCE_REPORTS),
        "last_report_ts": COMPLIANCE_LAST_REPORT_TS,
        "webhook_configured": bool(COMPLIANCE_WEBHOOK_URL.strip()),
        "email_configured": bool(COMPLIANCE_EMAIL_TO.strip()),
    }


@app.post("/auth/compliance/run")
def auth_compliance_run(request: Request, _role: str = Depends(_require_admin_dependency)) -> dict[str, object]:
    return _generate_compliance_report(trigger="manual")


@app.get("/auth/compliance/reports")
def auth_compliance_reports(request: Request, limit: int = 20, _role: str = Depends(_require_admin_dependency)) -> list[dict[str, object]]:
    n = max(1, min(limit, 200))
    return list(COMPLIANCE_REPORTS)[:n]


@app.get("/auth/compliance/reports/{report_id}")
def auth_compliance_report_by_id(report_id: str, request: Request, _role: str = Depends(_require_admin_dependency)) -> dict[str, object]:
    for report in COMPLIANCE_REPORTS:
        if report.get("id") == report_id:
            return report
    raise HTTPException(status_code=404, detail="Compliance report not found")


@app.get("/auth/compliance/deliveries")
def auth_compliance_deliveries(request: Request, limit: int = 50, _role: str = Depends(_require_admin_dependency)) -> list[dict[str, object]]:
    n = max(1, min(limit, 500))
    return list(COMPLIANCE_REPORT_DELIVERIES)[:n]


@app.post("/auth/compliance/purge")
def auth_compliance_purge(
    request: Request,
    audit_max_age_sec: int = 30 * 24 * 3600,
    worker_history_max_age_sec: int = 30 * 24 * 3600,
    ai_policy_audit_max_age_sec: int = 30 * 24 * 3600,
    drop_jwt_reject_telemetry: bool = False,
    _role: str = Depends(_require_admin_dependency),
) -> dict[str, int | bool]:
    now = int(time.time())
    audit_min_ts = now - max(0, audit_max_age_sec)
    worker_min_ts_iso = datetime.utcfromtimestamp(now - max(0, worker_history_max_age_sec)).isoformat()
    deleted_audit = service.delete_access_audit_older_than(audit_min_ts)
    deleted_worker_history = service.delete_worker_history_older_than(worker_min_ts_iso)
    deleted_ai_policy_audit = service.delete_ai_log_policy_audit_older_than(now - max(0, ai_policy_audit_max_age_sec))
    if drop_jwt_reject_telemetry:
        JWT_REJECT_TELEMETRY.clear()
        JWT_REJECT_BY_ISSUER_CLIENT.clear()
        JWT_REJECT_EVENTS.clear()
    return {
        "deleted_audit": deleted_audit,
        "deleted_worker_history": deleted_worker_history,
        "deleted_ai_policy_audit": deleted_ai_policy_audit,
        "jwt_reject_telemetry_cleared": drop_jwt_reject_telemetry,
    }


def _build_diagnostics_summary(history: list[dict]) -> dict:
    total = len(history)
    errors = sum(1 for r in history if r.get("last_error"))
    ok = total - errors
    accepted_sum = sum(int(r.get("accepted_events", 0)) for r in history)

    by_type: dict[str, dict[str, int]] = {}
    for r in history:
        ctype = str(r.get("collector_type", "unknown"))
        bucket = by_type.setdefault(ctype, {"ok": 0, "err": 0})
        if r.get("last_error"):
            bucket["err"] += 1
        else:
            bucket["ok"] += 1

    return {
        "runs": total,
        "ok": ok,
        "errors": errors,
        "accepted_events_sum": accepted_sum,
        "by_type": by_type,
    }


def _build_diagnostics_trend(history: list[dict]) -> dict:
    rows = list(reversed(history))
    points = [
        {
            "idx": i,
            "ts": str(r.get("ts", "")),
            "accepted_events": int(r.get("accepted_events", 0)),
            "has_error": bool(r.get("last_error")),
        }
        for i, r in enumerate(rows)
    ]
    return {"points": points}


@app.get("/worker/health")
def worker_health() -> dict[str, int | str | bool]:
    snap = _worker_health_snapshot()
    snap["status"] = "ok" if snap["running"] else "degraded"
    return snap


@app.get("/worker/history")
def worker_history(
    request: Request,
    limit: int = 100,
    target_id: str | None = None,
    collector_type: str | None = None,
    has_error: bool | None = None,
    tenant_id: str | None = None,
    _role: str = Depends(require_worker_history_read),
) -> list[dict]:
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    rows = worker.history(
        limit=limit,
        target_id=target_id,
        collector_type=collector_type,
        has_error=has_error,
    )
    return _filter_history_by_tenant(rows, tenant_scope)


@app.get("/worker/history.csv", response_class=PlainTextResponse)
def worker_history_csv(
    request: Request,
    limit: int = 200,
    target_id: str | None = None,
    collector_type: str | None = None,
    has_error: str | None = None,
    tenant_id: str | None = None,
    _role: str = Depends(require_worker_history_export),
) -> str:
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    rows = worker.history(
        limit=limit,
        target_id=target_id,
        collector_type=collector_type,
        has_error=has_error,
    )
    rows = _filter_history_by_tenant(rows, tenant_scope)
    header = "ts,target_id,collector_type,accepted_events,failure_streak,last_cursor,last_error"

    def esc(v: str) -> str:
        return '"' + v.replace('"', '""') + '"'

    lines = [header]
    for r in rows:
        line = ",".join(
            [
                esc(str(r.get("ts", ""))),
                esc(str(r.get("target_id", ""))),
                esc(str(r.get("collector_type", ""))),
                str(r.get("accepted_events", 0)),
                str(r.get("failure_streak", 0)),
                esc(str(r.get("last_cursor") or "")),
                esc(str(r.get("last_error") or "")),
            ]
        )
        lines.append(line)
    return "\n".join(lines)


@app.get("/worker/diagnostics/summary")
def worker_diagnostics_summary(
    request: Request,
    limit: int = 100,
    target_id: str | None = None,
    collector_type: str | None = None,
    has_error: str | None = None,
    role: str | None = None,
    tenant_id: str | None = None,
) -> dict:
    has_error_value = _parse_has_error_filter(has_error)
    role_value = _resolve_role_from_request(request, role, default_role="viewer")
    history_limit = min(limit, 40) if role_value == "viewer" else limit

    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    history = worker.history(
        limit=history_limit,
        target_id=target_id,
        collector_type=collector_type,
        has_error=has_error_value,
    )
    history = _filter_history_by_tenant(history, tenant_scope)
    return _build_diagnostics_summary(history)


@app.get("/worker/diagnostics/trend")
def worker_diagnostics_trend(
    request: Request,
    limit: int = 100,
    target_id: str | None = None,
    collector_type: str | None = None,
    has_error: str | None = None,
    role: str | None = None,
    tenant_id: str | None = None,
) -> dict:
    has_error_value = _parse_has_error_filter(has_error)
    role_value = _resolve_role_from_request(request, role, default_role="viewer")
    history_limit = min(limit, 40) if role_value == "viewer" else limit
    tenant_scope = _resolve_tenant_scope(request, tenant_id)

    history = worker.history(
        limit=history_limit,
        target_id=target_id,
        collector_type=collector_type,
        has_error=has_error_value,
    )
    history = _filter_history_by_tenant(history, tenant_scope)
    return _build_diagnostics_trend(history)


@app.get("/worker/diagnostics/stream")
async def worker_diagnostics_stream(
    request: Request,
    limit: int = 100,
    target_id: str | None = None,
    collector_type: str | None = None,
    has_error: str | None = None,
    tick_sec: float = 3.0,
    max_events: int | None = None,
    role: str | None = None,
    tenant_id: str | None = None,
) -> StreamingResponse:
    has_error_value = _parse_has_error_filter(has_error)
    role_value = _resolve_role_from_request(request, role, default_role="viewer")
    history_limit = min(limit, 40) if role_value == "viewer" else limit
    tenant_scope = _resolve_tenant_scope(request, tenant_id)

    async def event_stream():
        sent = 0
        while True:
            history = worker.history(
                limit=history_limit,
                target_id=target_id,
                collector_type=collector_type,
                has_error=has_error_value,
            )
            history = _filter_history_by_tenant(history, tenant_scope)
            payload = {
                "summary": _build_diagnostics_summary(history),
                "trend": _build_diagnostics_trend(history),
            }
            yield f"event: diagnostics\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
            sent += 1
            if max_events is not None and sent >= max_events:
                break
            await asyncio.sleep(max(tick_sec, 1.0))

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/ui/diagnostics", response_class=HTMLResponse)
def ui_diagnostics(
    request: Request,
    target_id: str = "",
    collector_type: str = "",
    has_error: str = "",
    role: str | None = None,
) -> str:
    has_error_value = _parse_has_error_filter(has_error)
    role_value = _resolve_role_from_request(request, role, default_role="viewer")

    history: list[dict]
    if _can_view_worker_history(role_value):
        history = worker.history(
            limit=100,
            target_id=target_id.strip() or None,
            collector_type=collector_type.strip() or None,
            has_error=has_error_value,
        )
    else:
        history = []
    rows = []
    for row in history:
        rows.append(
            f"<tr><td>{row.get('ts')}</td><td>{row.get('target_id')}</td><td>{row.get('collector_type')}</td>"
            f"<td>{row.get('accepted_events')}</td><td>{row.get('failure_streak')}</td><td>{row.get('last_cursor') or '-'}</td>"
            f"<td>{row.get('last_error') or '-'}</td></tr>"
        )
    rows_html = "".join(rows) if rows else "<tr><td colspan='7'>No worker history yet</td></tr>"
    qs = f"limit=100&target_id={target_id}&collector_type={collector_type}&has_error={has_error}&role={role_value}"

    return f"""
    <html><body style='font-family: Inter, Arial, sans-serif; max-width: 1200px; margin: 2rem auto; background:#f3f5f7; color:#111827;'>
      <h1>Worker diagnostics</h1>
      <p class='muted'>Current role: <b>{role_value}</b>{' (raw history limited by role)' if not _can_view_worker_history(role_value) else ''}</p>
      <p><a href='/dashboard'>← Dashboard</a> | <a href='/worker/health'>JSON health</a> | <a href='/worker/history'>JSON history</a> | <a href='/worker/history.csv'>CSV export</a></p>
      <div id='diag-summary' style='padding:10px;border:1px solid #ccc;background:#f8f8f8;margin:10px 0'>
        <b>Summary:</b> loading...
      </div>
      <h3>Errors by collector type</h3>
      <div id='diag-bars'><i>Loading chart...</i></div>
      <h3>Accepted events trend</h3>
      <div id='diag-trend'><i>Loading trend...</i></div>
      <form method='get' action='/ui/diagnostics' style='margin: 10px 0;'>
        <label>Target ID <input name='target_id' value='{target_id}' /></label>
        <label>Type
          <select name='collector_type'>
            <option value='' {'selected' if not collector_type else ''}>all</option>
            <option value='winrm' {'selected' if collector_type == 'winrm' else ''}>winrm</option>
            <option value='ssh' {'selected' if collector_type == 'ssh' else ''}>ssh</option>
            <option value='snmp' {'selected' if collector_type == 'snmp' else ''}>snmp</option>
          </select>
        </label>
        <label>Error
          <select name='has_error'>
            <option value='' {'selected' if has_error == '' else ''}>all</option>
            <option value='1' {'selected' if has_error == '1' else ''}>only errors</option>
            <option value='0' {'selected' if has_error == '0' else ''}>only ok</option>
          </select>
        </label>
        <label>Role
          <select name='role'>
            <option value='viewer' {'selected' if role_value == 'viewer' else ''}>viewer</option>
            <option value='operator' {'selected' if role_value == 'operator' else ''}>operator</option>
            <option value='admin' {'selected' if role_value == 'admin' else ''}>admin</option>
          </select>
        </label>
        <button type='submit'>Apply</button>
      </form>
      <p><a href='/worker/history.csv?target_id={target_id}&collector_type={collector_type}&has_error={has_error}&role={role_value}'>Download filtered CSV</a></p>
      <table border='0' cellpadding='8' cellspacing='0' style='width:100%;background:#fff;border:1px solid #d8dee4;border-radius:10px'>
        <thead><tr><th>TS</th><th>Target</th><th>Type</th><th>Accepted events</th><th>Failure streak</th><th>Cursor</th><th>Last error</th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
      <script>
        (function() {{
          const rawQs = "{qs}";
          const params = new URLSearchParams(rawQs);
          if (!params.get('target_id')) params.delete('target_id');
          if (!params.get('collector_type')) params.delete('collector_type');
          if (!params.get('has_error')) params.delete('has_error');
          const qs = params.toString();
          function renderDiagnostics(summary, trend) {{
            const s = document.getElementById('diag-summary');
            s.innerHTML = `<b>Summary:</b> runs=${{summary.runs}}, ok=${{summary.ok}}, errors=${{summary.errors}}, accepted_events_sum=${{summary.accepted_events_sum}}`;

            const bars = document.getElementById('diag-bars');
            const byType = summary.by_type || {{}};
            const keys = Object.keys(byType);
            if (!keys.length) {{
              bars.innerHTML = '<i>No data for chart</i>';
            }} else {{
              let maxTotal = 1;
              for (const k of keys) {{
                const t = (byType[k].ok || 0) + (byType[k].err || 0);
                if (t > maxTotal) maxTotal = t;
              }}
              bars.innerHTML = keys.sort().map((k) => {{
                const ok = byType[k].ok || 0;
                const err = byType[k].err || 0;
                const width = Math.floor(((ok + err) / maxTotal) * 240);
                const color = err > 0 ? '#d9534f' : '#5cb85c';
                return `<div><b>${{k}}</b> ok=${{ok}} err=${{err}}<div style='background:#ddd;width:240px;height:12px'><div style='background:${{color}};width:${{width}}px;height:12px'></div></div></div>`;
              }}).join('');
            }}

            const trendEl = document.getElementById('diag-trend');
            const points = trend.points || [];
            if (!points.length) {{
              trendEl.innerHTML = '<i>No trend data</i>';
            }} else {{
              const maxVal = Math.max(...points.map(p => p.accepted_events), 1);
              const polyPoints = points.map((p, i) => {{
                const x = 10 + i * 14;
                const y = 70 - Math.floor((p.accepted_events / maxVal) * 60);
                return `${{x}},${{y}}`;
              }}).join(' ');
              trendEl.innerHTML = `<svg width='760' height='90' style='border:1px solid #ddd;background:#fff'><polyline points='${{polyPoints}}' fill='none' stroke='#337ab7' stroke-width='2' /></svg>`;
            }}
          }}

          async function refreshDiagnostics() {{
            try {{
              const [summaryResp, trendResp] = await Promise.all([
                fetch('/worker/diagnostics/summary?' + qs),
                fetch('/worker/diagnostics/trend?' + qs)
              ]);
              const summary = await summaryResp.json();
              const trend = await trendResp.json();
              renderDiagnostics(summary, trend);
            }} catch (e) {{
              document.getElementById('diag-summary').innerHTML = '<b>Summary:</b> failed to load diagnostics';
            }}
          }}

          function startSSE() {{
            const sse = new EventSource('/worker/diagnostics/stream?' + qs);
            sse.addEventListener('diagnostics', (evt) => {{
              try {{
                const payload = JSON.parse(evt.data);
                renderDiagnostics(payload.summary || {{}}, payload.trend || {{ points: [] }});
              }} catch (err) {{
                console.error('SSE parse error', err);
              }}
            }});
            sse.onerror = () => {{
              sse.close();
              refreshDiagnostics();
              setInterval(refreshDiagnostics, 10000);
            }};
          }}

          if (window.EventSource) {{
            startSSE();
          }} else {{
            refreshDiagnostics();
            setInterval(refreshDiagnostics, 10000);
          }}
        }})();
      </script>

    </body></html>
    """




def _dashboard_permissions(role: str) -> dict[str, bool]:
    role_value = role if role in {"viewer", "operator", "admin"} else "viewer"
    return {
        "show_worker_health": role_value in {"operator", "admin"},
        "show_recent_alerts": role_value in {"operator", "admin"},
        "show_collectors_link": role_value in {"operator", "admin"},
        "show_diagnostics_link": role_value in {"operator", "admin"},
        "show_filters": True,
    }

def _build_dashboard_payload(
    period_days: int = 30,
    asset_id: str | None = None,
    source: str | None = None,
    role: str = "viewer",
    tenant_id: str | None = None,
) -> dict:
    overview_data = service.overview()
    worker_health_data = _worker_health_snapshot()
    role_value = role if role in {"viewer", "operator", "admin"} else "viewer"
    permissions = _dashboard_permissions(role_value)

    assets = [a for a in service.list_assets() if _asset_in_tenant(a.id, tenant_id)]
    asset_event_counts: dict[str, int] = {}
    all_events = []
    for asset in assets:
        events = service.list_events(asset.id)
        asset_event_counts[asset.id] = len(events)
        all_events.extend(events)

    cutoff = datetime.utcnow() - timedelta(days=max(period_days, 1))
    filtered_events = [
        e
        for e in all_events
        if (not asset_id or e.asset_id == asset_id)
        and (not source or e.source == source)
        and (e.timestamp.replace(tzinfo=None) if e.timestamp.tzinfo else e.timestamp) >= cutoff
    ]

    source_counts = Counter(e.source for e in filtered_events)
    severity_counts = Counter(e.severity.value for e in filtered_events)
    total_events = max(len(filtered_events), 1)

    windows_events = source_counts.get("windows_eventlog", 0)
    syslog_events = source_counts.get("syslog", 0)
    agentless_events = sum(v for k, v in source_counts.items() if k.startswith("agentless_"))

    trend_counts: Counter[str] = Counter()
    for e in filtered_events:
        month = str(e.timestamp)[:7]
        trend_counts[month] += 1
    trend_labels = sorted(trend_counts.keys())[-6:]
    trend_values = [trend_counts[m] for m in trend_labels]

    filtered_asset_counts = Counter(e.asset_id for e in filtered_events)

    top_assets = [
        {"asset_id": aid, "events": cnt}
        for aid, cnt in sorted(filtered_asset_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
    ]
    recent_alerts = [
        {
            "source": e.source,
            "message": e.message,
            "severity": e.severity.value,
            "timestamp": str(e.timestamp),
        }
        for e in sorted(filtered_events, key=lambda x: str(x.timestamp), reverse=True)
        if e.severity.value in ("warning", "critical")
    ][:7]

    assets_rows = []
    for asset in assets:
        if asset_id and asset.id != asset_id:
            continue
        assets_rows.append(
            {
                "id": asset.id,
                "asset_type": asset.asset_type.value,
                "location": asset.location or "-",
                "events": int(filtered_asset_counts.get(asset.id, 0)),
                "alerts": len(service.build_alerts(asset.id)),
                "insights": len(service.build_correlation_insights(asset.id)),
            }
        )

    return {
        "overview": {**overview_data, "events_filtered": len(filtered_events)},
        "worker_health": worker_health_data,
        "sources": {
            "windows": windows_events,
            "syslog": syslog_events,
            "agentless": agentless_events,
            "windows_pct": int((windows_events / total_events) * 100),
            "syslog_pct": int((syslog_events / total_events) * 100),
            "agentless_pct": int((agentless_events / total_events) * 100),
        },
        "trend": {"labels": trend_labels, "values": trend_values},
        "severity": {
            "info": severity_counts.get("info", 0),
            "warning": severity_counts.get("warning", 0),
            "critical": severity_counts.get("critical", 0),
        },
        "top_assets": top_assets,
        "recent_alerts": recent_alerts,
        "assets_table": assets_rows,
        "filters": {"period_days": period_days, "asset_id": asset_id or "", "source": source or "", "tenant_id": tenant_id or ""},
        "filter_options": {
            "assets": [{"id": a.id, "name": a.name} for a in assets],
            "sources": sorted({e.source for e in all_events}),
            "roles": ["viewer", "operator", "admin"],
        },
        "role": role_value,
        "permissions": permissions,
    }


@app.get("/dashboard/data")
def dashboard_data(
    request: Request,
    period_days: int = 30,
    asset_id: str = "",
    source: str = "",
    role: str | None = None,
    tenant_id: str = "",
) -> dict:
    role_value = _resolve_role_from_request(request, role, default_role="viewer")
    tenant_scope = _resolve_tenant_scope(request, tenant_id.strip() or None)
    return _build_dashboard_payload(
        period_days=period_days,
        asset_id=asset_id.strip() or None,
        source=source.strip() or None,
        role=role_value,
        tenant_id=tenant_scope,
    )


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    period_days: int = 30,
    asset_id: str = "",
    source: str = "",
    role: str | None = None,
    tenant_id: str = "",
) -> str:
    role_value = _resolve_role_from_request(request, role, default_role="viewer")
    tenant_scope = _resolve_tenant_scope(request, tenant_id.strip() or None)
    payload = _build_dashboard_payload(
        period_days=period_days,
        asset_id=asset_id.strip() or None,
        source=source.strip() or None,
        role=role_value,
        tenant_id=tenant_scope,
    )
    pjson = json.dumps(payload)
    return f"""
    <html><head><style>
      body {{ font-family: Inter, Arial, sans-serif; margin:0; background:#f3f5f7; color:#1f2937; }}
      .topbar {{ background:#344452; color:#fff; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; }}
      .nav a {{ color:#dce6ee; margin-right:14px; text-decoration:none; font-size:14px; }}
      .container {{ max-width:1400px; margin:18px auto; padding:0 16px; }}
      .cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:14px; }}
      .card {{ background:#fff; border:1px solid #d8dee4; border-radius:10px; padding:16px; box-shadow:0 1px 2px rgba(0,0,0,.04); }}
      .metric {{ font-size:34px; font-weight:700; margin-top:8px; }}
      .muted {{ color:#64748b; font-size:13px; }}
      .ring {{ width:72px; height:72px; border-radius:50%; margin-left:auto; }}
      .grid {{ display:grid; grid-template-columns:1.2fr 1.2fr 1fr; gap:14px; }}
      .panel {{ background:#fff; border:1px solid #d8dee4; border-radius:10px; padding:16px; }}
      h2 {{ margin:0 0 10px 0; font-size:24px; }}
      h3 {{ margin:0 0 12px 0; font-size:28px; }}
      table {{ width:100%; border-collapse:collapse; }}
      th,td {{ border-bottom:1px solid #edf2f7; text-align:left; padding:8px; font-size:13px; }}
      .alert-item {{ border-left:4px solid #94a3b8; background:#f8fafc; padding:8px 10px; margin-bottom:8px; }}
      .alert-item.warning {{ border-left-color:#f59e0b; }}
      .alert-item.critical {{ border-left-color:#dc2626; }}
      .alert-title {{ font-size:14px; }}
      .alert-ts {{ font-size:12px; color:#64748b; margin-top:4px; }}
      .health {{ margin:10px 0 14px; padding:10px 12px; background:#fff; border:1px solid #d8dee4; border-radius:8px; }}
      .small {{ font-size:12px; color:#64748b; }}
    </style></head>
    <body>
      <div class='topbar'>
        <div><b>InfraMind Monitor</b></div>
        <div class='nav'>
          <a href='/ui/assets'>Assets</a><a href='/ui/events'>Events</a><a href='/ui/ai'>AI Analytics</a><a href='/ui/ai/policies'>AI Policies</a><a id='nav-collectors' href='/ui/collectors'>Collectors</a><a id='nav-diagnostics' href='/ui/diagnostics'>Diagnostics</a><a href='/ui/auth'>Auth</a><a href='/ui/compliance'>Compliance</a>
        </div>
      </div>
      <div class='container' id='dashboard-root' data-api='/dashboard/data' data-period-days='{payload["filters"]["period_days"]}' data-asset-id='{payload["filters"]["asset_id"]}' data-source='{payload["filters"]["source"]}' data-role='{payload["role"]}' data-tenant-id='{payload["filters"].get("tenant_id","")}'>
        <h2>Events Overview</h2>
        <form id='dashboard-filters' style='display:flex;gap:8px;align-items:center;margin:8px 0 14px'>
          <label>Period
            <select name='period_days' id='flt-period'>
              <option value='7'>7d</option>
              <option value='30' selected>30d</option>
              <option value='90'>90d</option>
            </select>
          </label>
          <label>Asset <select name='asset_id' id='flt-asset'><option value=''>all</option></select></label>
          <label>Source <select name='source' id='flt-source'><option value=''>all</option></select></label>
          <label>Role
            <select name='role' id='flt-role'>
              <option value='viewer'>viewer</option>
              <option value='operator'>operator</option>
              <option value='admin'>admin</option>
            </select>
          </label>
          <button type='submit'>Apply</button>
        </form>
        <div class='cards'>
          <div class='card'><div class='muted'>All Events</div><div class='metric' id='kpi-all'>0</div><div class='small' id='kpi-assets'>Across 0 assets</div></div>
          <div class='card'><div class='muted'>Windows Events</div><div class='metric' id='kpi-win'>0</div><div class='small' id='kpi-win-pct'>0% of all events</div></div>
          <div class='card'><div class='muted'>Syslog Events</div><div class='metric' id='kpi-syslog'>0</div><div class='small' id='kpi-syslog-pct'>0% of all events</div></div>
          <div class='card' style='display:flex;align-items:center;gap:8px'><div><div class='muted'>Agentless Events</div><div class='metric' style='font-size:30px' id='kpi-agentless'>0</div><div class='small' id='kpi-agentless-pct'>0% of all events</div></div><div class='ring' id='kpi-ring'></div></div>
        </div>

        <div class='health' id='worker-health'><b>Worker health:</b> loading... | <a href='/worker/health'>JSON</a></div>

        <div class='grid'>
          <div class='panel'>
            <h3>Logs Trend</h3>
            <svg width='560' height='170' style='max-width:100%;background:#fff' id='trend-svg'></svg>
          </div>
          <div class='panel'>
            <h3>Top 5 Assets</h3>
            <table>
              <thead><tr><th>Asset</th><th>Events</th></tr></thead>
              <tbody id='top-assets-rows'><tr><td colspan='2'>No data</td></tr></tbody>
            </table>
            <div style='margin-top:16px'>
              <div class='muted'>Severity Distribution</div>
              <table><tbody id='severity-rows'></tbody></table>
            </div>
          </div>
          <div class='panel' id='recent-alerts-panel'>
            <h3>Recent Alerts</h3>
            <div id='recent-alerts'><div class='muted'>No warning/critical events yet.</div></div>
          </div>
        </div>

        <div class='panel' style='margin-top:14px'>
          <h3 style='font-size:20px'>Assets table</h3>
          <table>
            <thead><tr><th>Asset</th><th>Type</th><th>Location</th><th>Events</th><th>Alerts</th><th>Insights</th></tr></thead>
            <tbody id='assets-rows'><tr><td colspan='6'>No assets yet</td></tr></tbody>
          </table>
        </div>
      </div>
      <script>window.__DASHBOARD_INITIAL__ = {pjson};</script>
      <script type='module' src='/static/dashboard.js'></script>
    </body></html>
    """


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/overview", response_model=Overview)
def overview() -> Overview:
    return Overview(**service.overview())


@app.get("/assets", response_model=list[Asset])
def list_assets(request: Request, tenant_id: str | None = None) -> list[Asset]:
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    return [a for a in service.list_assets() if _asset_in_tenant(a.id, tenant_scope)]


@app.post("/assets", response_model=Asset)
def upsert_asset(request: Request, asset: Asset, _role: str = Depends(_require_operator_dependency)) -> Asset:
    return service.upsert_asset(asset)


@app.get("/collectors", response_model=list[CollectorTargetPublic])
def list_collectors(request: Request, _role: str = Depends(_require_operator_dependency)) -> list[CollectorTargetPublic]:
    return [CollectorTargetPublic.from_target(t) for t in service.list_collector_targets()]


@app.post("/collectors", response_model=CollectorTarget)
def upsert_collector(request: Request, target: CollectorTarget, _role: str = Depends(_require_operator_dependency)) -> CollectorTarget:
    try:
        return service.upsert_collector_target(target)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.delete("/collectors/{target_id}")
def delete_collector(request: Request, target_id: str, _role: str = Depends(_require_operator_dependency)) -> dict[str, str]:
    service.delete_collector_target(target_id)
    return {"status": "deleted"}


@app.get("/worker/status")
def worker_status() -> dict:
    status = worker.status()
    status["enabled"] = ENABLE_AGENTLESS_WORKER
    return status


@app.get("/worker/targets")
def worker_targets(request: Request, _role: str = Depends(_require_operator_dependency)) -> list[dict]:
    return worker.target_status()


@app.post("/worker/run-once")
def worker_run_once(request: Request, _role: str = Depends(_require_operator_dependency)) -> dict[str, int]:
    accepted = worker.run_once()
    return {"accepted": accepted}


@app.post("/events", response_model=Event)
def register_event(request: Request, event: Event, _role: str = Depends(_require_operator_dependency)) -> Event:
    try:
        stored, _ = service.register_event(event)
        return stored
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/ingest/events", response_model=IngestSummary)
def register_events_batch(request: Request, batch: EventBatch, _role: str = Depends(_require_operator_dependency)) -> IngestSummary:
    try:
        accepted = service.register_events_batch(batch.events)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return IngestSummary(accepted=accepted)


@app.get("/assets/{asset_id}/events", response_model=list[Event])
def list_events(request: Request, asset_id: str, tenant_id: str | None = None) -> list[Event]:
    if not _asset_exists(asset_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    if not _asset_in_tenant(asset_id, tenant_scope):
        raise HTTPException(status_code=403, detail="Asset is out of tenant scope")
    return service.list_events(asset_id)


@app.get("/assets/{asset_id}/alerts", response_model=list[Alert])
def list_alerts(request: Request, asset_id: str, tenant_id: str | None = None) -> list[Alert]:
    if not _asset_exists(asset_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    if not _asset_in_tenant(asset_id, tenant_scope):
        raise HTTPException(status_code=403, detail="Asset is out of tenant scope")
    return service.build_alerts(asset_id)


@app.get("/assets/{asset_id}/insights", response_model=list[CorrelationInsight])
def list_insights(request: Request, asset_id: str, tenant_id: str | None = None) -> list[CorrelationInsight]:
    if not _asset_exists(asset_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    if not _asset_in_tenant(asset_id, tenant_scope):
        raise HTTPException(status_code=403, detail="Asset is out of tenant scope")
    return service.build_correlation_insights(asset_id)




@app.get("/ai-log-analytics/policies", response_model=list[LogAnalyticsPolicy])
def list_ai_log_policies(request: Request, enabled_only: bool = False, tenant_id: str | None = None, _role: str = Depends(_require_operator_dependency)) -> list[LogAnalyticsPolicy]:
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    return service.list_ai_log_policies(enabled_only=enabled_only, tenant_id=tenant_scope)


@app.post("/ai-log-analytics/policies", response_model=LogAnalyticsPolicy)
def upsert_ai_log_policy(request: Request, policy: LogAnalyticsPolicy, tenant_id: str | None = None, _role: str = Depends(_require_operator_dependency)) -> LogAnalyticsPolicy:
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    if tenant_scope and policy.tenant_id and policy.tenant_id != tenant_scope:
        raise HTTPException(status_code=403, detail="Policy tenant is out of scope")
    if tenant_scope and not policy.tenant_id:
        policy = policy.model_copy(update={"tenant_id": tenant_scope})
    before = service.storage.get_ai_log_policy(policy.id, tenant_id=tenant_scope)
    stored = service.upsert_ai_log_policy(policy)
    service.add_ai_log_policy_audit(
        LogAnalyticsPolicyAuditEntry(
            ts=int(time.time()),
            policy_id=stored.id,
            tenant_id=stored.tenant_id,
            action="upsert",
            actor_role=getattr(request.state, "auth_context", _resolve_auth_context_from_request(request, None, default_role="viewer")).role,
            details=_build_policy_audit_details("upsert", before=before, after=stored),
        )
    )
    return stored


@app.delete("/ai-log-analytics/policies/{policy_id}")
def delete_ai_log_policy(request: Request, policy_id: str, tenant_id: str | None = None, _role: str = Depends(_require_operator_dependency)) -> dict[str, str]:
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    try:
        before = service.storage.get_ai_log_policy(policy_id, tenant_id=tenant_scope)
        service.delete_ai_log_policy(policy_id, tenant_id=tenant_scope)
        service.add_ai_log_policy_audit(
            LogAnalyticsPolicyAuditEntry(
                ts=int(time.time()),
                policy_id=policy_id,
                tenant_id=tenant_scope,
                action="delete",
                actor_role=getattr(request.state, "auth_context", _resolve_auth_context_from_request(request, None, default_role="viewer")).role,
                details=_build_policy_audit_details("delete", before=before),
            )
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"deleted": policy_id}


@app.get("/ai-log-analytics/policies/audit", response_model=list[LogAnalyticsPolicyAuditEntry])
def list_ai_log_policy_audit(
    request: Request,
    limit: int = 100,
    tenant_id: str | None = None,
    action: str | None = None,
    policy_id: str | None = None,
    min_ts: int | None = None,
    max_ts: int | None = None,
    sort: str = "desc",
    offset: int = 0,
    changed_field: str | None = None,
    _role: str = Depends(_require_admin_dependency),
) -> list[LogAnalyticsPolicyAuditEntry]:
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    sort_norm = str(sort).strip().lower()
    if sort_norm not in {"asc", "desc"}:
        raise HTTPException(status_code=422, detail="sort must be 'asc' or 'desc'")
    return service.list_ai_log_policy_audit(
        limit=limit,
        tenant_id=tenant_scope,
        action=action.strip() if action else None,
        policy_id=policy_id.strip() if policy_id else None,
        min_ts=min_ts,
        max_ts=max_ts,
        sort=sort_norm,
        offset=max(0, offset),
        changed_field=changed_field.strip() if changed_field else None,
    )


@app.get("/ai-log-analytics/policies/audit/parsed", response_model=list[LogAnalyticsPolicyAuditEntryParsed])
def list_ai_log_policy_audit_parsed(
    request: Request,
    limit: int = 100,
    tenant_id: str | None = None,
    action: str | None = None,
    policy_id: str | None = None,
    changed_field: str | None = None,
    min_ts: int | None = None,
    max_ts: int | None = None,
    sort: str = "desc",
    offset: int = 0,
    _role: str = Depends(_require_admin_dependency),
) -> list[LogAnalyticsPolicyAuditEntryParsed]:
    rows = list_ai_log_policy_audit(
        request=request,
        limit=limit,
        tenant_id=tenant_id,
        action=action,
        policy_id=policy_id,
        changed_field=changed_field,
        min_ts=min_ts,
        max_ts=max_ts,
        sort=sort,
        offset=offset,
        _role=_role,
    )
    return [
        LogAnalyticsPolicyAuditEntryParsed(
            **row.model_dump(),
            details_json=_parse_policy_audit_details(row.details),
        )
        for row in rows
    ]


@app.get("/ai-log-analytics/policies/audit.csv", response_class=PlainTextResponse)
def ai_log_policy_audit_csv(
    request: Request,
    limit: int = 1000,
    tenant_id: str | None = None,
    action: str | None = None,
    policy_id: str | None = None,
    min_ts: int | None = None,
    max_ts: int | None = None,
    sort: str = "desc",
    offset: int = 0,
    changed_field: str | None = None,
    _role: str = Depends(_require_admin_dependency),
) -> str:
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    sort_norm = sort.strip().lower()
    if sort_norm not in {"asc", "desc"}:
        raise HTTPException(status_code=422, detail="sort must be 'asc' or 'desc'")
    rows = service.list_ai_log_policy_audit(
        limit=limit,
        tenant_id=tenant_scope,
        action=action.strip() if action else None,
        policy_id=policy_id.strip() if policy_id else None,
        min_ts=min_ts,
        max_ts=max_ts,
        sort=sort_norm,
        offset=max(0, offset),
        changed_field=changed_field.strip() if changed_field else None,
    )
    header = 'ts,policy_id,tenant_id,action,actor_role,details\n'
    body = ''.join(
        f'"{row.ts}","{row.policy_id}","{row.tenant_id or ""}","{row.action}","{row.actor_role}","{row.details}"\n'
        for row in rows
    )
    return header + body


@app.get("/assets/{asset_id}/ai-log-analytics/policy-dry-run", response_model=LogAnalyticsPolicyDryRun)
def ai_log_policy_dry_run(
    request: Request,
    asset_id: str,
    limit: int = 300,
    ignore_sources: str = "",
    ignore_signatures: str = "",
    policy_id: str | None = None,
    policy_ids: str = "",
    policy_merge_strategy: PolicyMergeStrategy = PolicyMergeStrategy.union,
    impact_mode: str = "weighted",
    tenant_id: str | None = None,
) -> LogAnalyticsPolicyDryRun:
    if not _asset_exists(asset_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    if not _asset_in_tenant(asset_id, tenant_scope):
        raise HTTPException(status_code=403, detail="Asset is out of tenant scope")

    parsed_ignore_sources = {item.strip().lower() for item in ignore_sources.split(",") if item.strip()}
    parsed_ignore_signatures = {item.strip().lower() for item in ignore_signatures.split(",") if item.strip()}
    parsed_policy_ids = [item.strip() for item in policy_ids.split(",") if item.strip()]

    try:
        return service.preview_ai_log_policy_effect(
            asset_id=asset_id,
            ignore_sources=parsed_ignore_sources,
            ignore_signatures=parsed_ignore_signatures,
            policy_id=policy_id,
            policy_ids=parsed_policy_ids,
            merge_strategy=policy_merge_strategy,
            limit=min(max(limit, 20), 2000),
            tenant_id=tenant_scope,
            impact_mode=impact_mode,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/ai-log-analytics/overview", response_model=LogAnalyticsOverview)
def get_ai_log_analytics_overview(
    request: Request,
    limit_per_asset: int = 300,
    max_assets: int = 50,
    max_clusters: int = 30,
    max_anomalies: int = 20,
    ignore_sources: str = "",
    ignore_signatures: str = "",
    policy_id: str | None = None,
    policy_ids: str = "",
    policy_merge_strategy: PolicyMergeStrategy = PolicyMergeStrategy.union,
    tenant_id: str | None = None,
) -> LogAnalyticsOverview:
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    parsed_ignore_sources = {item.strip().lower() for item in ignore_sources.split(",") if item.strip()}
    parsed_ignore_signatures = {item.strip().lower() for item in ignore_signatures.split(",") if item.strip()}
    parsed_policy_ids = [item.strip() for item in policy_ids.split(",") if item.strip()]
    tenant_assets = {asset.id for asset in service.list_assets() if _asset_in_tenant(asset.id, tenant_scope)}

    try:
        resolved_sources, resolved_signatures = service.resolve_ai_log_filters(
            ignore_sources=parsed_ignore_sources,
            ignore_signatures=parsed_ignore_signatures,
            policy_id=policy_id,
            policy_ids=parsed_policy_ids,
            merge_strategy=policy_merge_strategy,
            tenant_id=tenant_scope,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return service.build_log_analytics_overview(
        limit_per_asset=min(max(limit_per_asset, 20), 2000),
        max_assets=min(max(max_assets, 1), 200),
        max_clusters=min(max(max_clusters, 5), 100),
        max_anomalies=min(max(max_anomalies, 1), 100),
        ignore_sources=resolved_sources,
        ignore_signatures=resolved_signatures,
        asset_ids=tenant_assets,
    )


@app.get("/assets/{asset_id}/ai-log-analytics", response_model=LogAnalyticsInsight)
def get_ai_log_analytics(
    request: Request,
    asset_id: str,
    limit: int = 300,
    max_clusters: int = 30,
    max_anomalies: int = 20,
    ignore_sources: str = "",
    ignore_signatures: str = "",
    policy_id: str | None = None,
    policy_ids: str = "",
    policy_merge_strategy: PolicyMergeStrategy = PolicyMergeStrategy.union,
    tenant_id: str | None = None,
) -> LogAnalyticsInsight:
    if not _asset_exists(asset_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    if not _asset_in_tenant(asset_id, tenant_scope):
        raise HTTPException(status_code=403, detail="Asset is out of tenant scope")
    try:
        parsed_ignore_sources = {item.strip().lower() for item in ignore_sources.split(",") if item.strip()}
        parsed_ignore_signatures = {item.strip().lower() for item in ignore_signatures.split(",") if item.strip()}
        parsed_policy_ids = [item.strip() for item in policy_ids.split(",") if item.strip()]
        resolved_sources, resolved_signatures = service.resolve_ai_log_filters(
            ignore_sources=parsed_ignore_sources,
            ignore_signatures=parsed_ignore_signatures,
            policy_id=policy_id,
            policy_ids=parsed_policy_ids,
            merge_strategy=policy_merge_strategy,
            tenant_id=tenant_scope,
        )
        return service.build_log_analytics(
            asset_id,
            limit=min(max(limit, 20), 2000),
            max_clusters=min(max(max_clusters, 5), 100),
            max_anomalies=min(max(max_anomalies, 1), 100),
            ignore_sources=resolved_sources,
            ignore_signatures=resolved_signatures,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

@app.get("/assets/{asset_id}/recommendation", response_model=Recommendation)
def get_recommendation(request: Request, asset_id: str, tenant_id: str | None = None) -> Recommendation:
    tenant_scope = _resolve_tenant_scope(request, tenant_id)
    if not _asset_in_tenant(asset_id, tenant_scope):
        raise HTTPException(status_code=403, detail="Asset is out of tenant scope")
    try:
        return service.build_recommendation(asset_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
