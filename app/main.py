import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from app.models import (
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


@asynccontextmanager
async def lifespan(_: FastAPI):
    if ENABLE_AGENTLESS_WORKER:
        worker.start()
    try:
        yield
    finally:
        worker.stop()


app = FastAPI(title="InfraMind Monitor API", version="0.9.0", lifespan=lifespan)


def _asset_exists(asset_id: str) -> bool:
    return any(a.id == asset_id for a in service.list_assets())


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return """
    <html><body style='font-family: Arial; max-width: 920px; margin: 2rem auto;'>
      <h1>InfraMind Monitor</h1>
      <ul>
        <li><a href='/dashboard'>Dashboard</a></li>
        <li><a href='/ui/assets'>UI: Add/List Assets</a></li>
        <li><a href='/ui/events'>UI: Add Event</a></li>
        <li><a href='/ui/collectors'>UI: Agentless Collectors</a></li>
        <li><a href='/worker/status'>Worker status</a></li>
        <li><a href='/worker/targets'>Worker targets</a></li>
        <li><a href='/ui/diagnostics'>UI: Worker diagnostics</a></li>
        <li><a href='/docs'>Swagger UI</a></li>
      </ul>
      <p>Now you can manage assets/events via web forms, and configure future agentless collectors.</p>
    </body></html>
    """


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
    <html><body style='font-family: Arial; max-width: 1200px; margin: 2rem auto;'>
      <h1>Agentless Collector Targets</h1>
      <p><a href='/dashboard'>← Dashboard</a> | <a href='/ui/assets'>Manage assets</a></p>
      <form method='post' action='/ui/collectors'>
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
      <table border='1' cellpadding='8' cellspacing='0'>
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
    <html><body style='font-family: Arial; max-width: 980px; margin: 2rem auto;'>
      <h1>Assets</h1>
      <p><a href='/dashboard'>← Dashboard</a></p>
      <form method='post' action='/ui/assets'>
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
      <table border='1' cellpadding='8' cellspacing='0'>
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
    <html><body style='font-family: Arial; max-width: 1100px; margin: 2rem auto;'>
      <h1>Asset detail: {asset.id}</h1>
      <p><a href='/ui/assets'>← Back to assets</a> | <a href='/dashboard'>Dashboard</a></p>
      <p><b>Name:</b> {asset.name} | <b>Type:</b> {asset.asset_type.value} | <b>Location:</b> {asset.location or '-'}</p>
      <h2>Recommendation</h2>
      <p><b>Risk score:</b> {rec.risk_score} — {rec.summary}</p>
      <ul>{actions}</ul>
      <h2>Correlation insights</h2>
      <ul>{insights_rows}</ul>
      <h2>Recent events</h2>
      <table border='1' cellpadding='8' cellspacing='0'>
        <thead><tr><th>Timestamp</th><th>Source</th><th>Severity</th><th>Message</th></tr></thead>
        <tbody>{event_rows}</tbody>
      </table>
    </body></html>
    """


@app.get("/ui/events", response_class=HTMLResponse)
def ui_events() -> str:
    options = "".join(f"<option value='{a.id}'>{a.id} ({a.name})</option>" for a in service.list_assets())
    if not options:
        options = "<option value=''>No assets. Create one first.</option>"

    return f"""
    <html><body style='font-family: Arial; max-width: 980px; margin: 2rem auto;'>
      <h1>Add Event</h1>
      <p><a href='/dashboard'>← Dashboard</a> | <a href='/ui/assets'>Manage assets</a></p>
      <form method='post' action='/ui/events'>
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


def _parse_has_error(has_error: str) -> bool | None:
    if has_error == "1":
        return True
    if has_error == "0":
        return False
    return None


def _worker_history_summary(history: list[dict]) -> dict[str, int]:
    total = len(history)
    errors = sum(1 for r in history if r.get("last_error"))
    return {
        "runs": total,
        "ok": total - errors,
        "errors": errors,
        "accepted_events_sum": sum(int(r.get("accepted_events", 0)) for r in history),
    }


def _worker_history_by_type(history: list[dict]) -> list[dict[str, int | str]]:
    by_type: dict[str, dict[str, int]] = {}
    for r in history:
        ctype = str(r.get("collector_type", "unknown"))
        bucket = by_type.setdefault(ctype, {"ok": 0, "errors": 0})
        if r.get("last_error"):
            bucket["errors"] += 1
        else:
            bucket["ok"] += 1
    return [
        {
            "collector_type": ctype,
            "ok": values["ok"],
            "errors": values["errors"],
            "runs": values["ok"] + values["errors"],
        }
        for ctype, values in sorted(by_type.items())
    ]


def _worker_history_trend(history: list[dict]) -> list[dict[str, int | str]]:
    return [
        {"ts": str(r.get("ts", "")), "accepted_events": int(r.get("accepted_events", 0))}
        for r in history[::-1]
    ]


@app.get("/worker/health")
def worker_health() -> dict[str, int | str | bool]:
    snap = _worker_health_snapshot()
    snap["status"] = "ok" if snap["running"] else "degraded"
    return snap


@app.get("/worker/history")
def worker_history(
    limit: int = 100,
    target_id: str | None = None,
    collector_type: str | None = None,
    has_error: bool | None = None,
) -> list[dict]:
    return worker.history(
        limit=limit,
        target_id=target_id,
        collector_type=collector_type,
        has_error=has_error,
    )


@app.get("/worker/history/summary")
def worker_history_summary(
    limit: int = 100,
    target_id: str | None = None,
    collector_type: str | None = None,
    has_error: bool | None = None,
) -> dict:
    history = worker.history(
        limit=limit,
        target_id=target_id,
        collector_type=collector_type,
        has_error=has_error,
    )
    return {
        "summary": _worker_history_summary(history),
        "by_collector_type": _worker_history_by_type(history),
        "trend": _worker_history_trend(history),
    }


@app.get("/worker/history.csv", response_class=PlainTextResponse)
def worker_history_csv(
    limit: int = 200,
    target_id: str | None = None,
    collector_type: str | None = None,
    has_error: bool | None = None,
) -> str:
    rows = worker.history(
        limit=limit,
        target_id=target_id,
        collector_type=collector_type,
        has_error=has_error,
    )
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


@app.get("/ui/diagnostics", response_class=HTMLResponse)
def ui_diagnostics(
    target_id: str = "",
    collector_type: str = "",
    has_error: str = "",
) -> str:
    has_error_value = _parse_has_error(has_error)

    history = worker.history(
        limit=100,
        target_id=target_id.strip() or None,
        collector_type=collector_type.strip() or None,
        has_error=has_error_value,
    )
    rows = []
    for row in history:
        rows.append(
            f"<tr><td>{row.get('ts')}</td><td>{row.get('target_id')}</td><td>{row.get('collector_type')}</td>"
            f"<td>{row.get('accepted_events')}</td><td>{row.get('failure_streak')}</td><td>{row.get('last_cursor') or '-'}</td>"
            f"<td>{row.get('last_error') or '-'}</td></tr>"
        )
    rows_html = "".join(rows) if rows else "<tr><td colspan='7'>No worker history yet</td></tr>"

    summary = _worker_history_summary(history)

    by_type = _worker_history_by_type(history)

    bars = []
    max_total = max((int(v["runs"]) for v in by_type), default=1)
    for v in by_type:
        ctype = str(v["collector_type"])
        width = int((int(v["runs"]) / max_total) * 240)
        bars.append(
            f"<div><b>{ctype}</b> ok={v['ok']} err={v['errors']}<div style='background:#ddd;width:240px;height:12px'>"
            f"<div style='background:{'#d9534f' if v['errors'] else '#5cb85c'};width:{width}px;height:12px'></div></div></div>"
        )
    bars_html = "".join(bars) or "<i>No data for chart</i>"

    trend_points = []
    trend_values = [int(r["accepted_events"]) for r in _worker_history_trend(history)]
    max_val = max(trend_values, default=1)
    for i, val in enumerate(trend_values):
        x = 10 + i * 14
        y = 70 - int((val / max_val) * 60) if max_val else 70
        trend_points.append(f"{x},{y}")
    poly = " ".join(trend_points)
    trend_svg = (
        f"<svg width='760' height='90' style='border:1px solid #ddd;background:#fff'>"
        f"<polyline points='{poly}' fill='none' stroke='#337ab7' stroke-width='2' />"
        f"</svg>"
        if trend_points
        else "<i>No trend data</i>"
    )

    return f"""
    <html><body style='font-family: Arial; max-width: 1200px; margin: 2rem auto;'>
      <h1>Worker diagnostics</h1>
      <p><a href='/dashboard'>← Dashboard</a> | <a href='/worker/health'>JSON health</a> | <a href='/worker/history'>JSON history</a> | <a href='/worker/history.csv'>CSV export</a></p>
      <div style='padding:10px;border:1px solid #ccc;background:#f8f8f8;margin:10px 0'>
        <b>Summary:</b> runs={summary['runs']}, ok={summary['ok']}, errors={summary['errors']}, accepted_events_sum={summary['accepted_events_sum']}
      </div>
      <h3>Errors by collector type</h3>
      {bars_html}
      <h3>Accepted events trend</h3>
      {trend_svg}
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
        <button type='submit'>Apply</button>
      </form>
      <p><a href='/worker/history.csv?target_id={target_id}&collector_type={collector_type}&has_error={has_error}'>Download filtered CSV</a></p>
      <table border='1' cellpadding='8' cellspacing='0'>
        <thead><tr><th>TS</th><th>Target</th><th>Type</th><th>Accepted events</th><th>Failure streak</th><th>Cursor</th><th>Last error</th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
    </body></html>
    """


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> str:
    overview_data = service.overview()
    worker_health_data = _worker_health_snapshot()

    assets = service.list_assets()
    severity_counts = {"info": 0, "warning": 0, "critical": 0}
    asset_rows = []
    recent_alerts: list[str] = []

    for asset in assets:
        events = service.list_events(asset.id)
        alerts = service.build_alerts(asset.id)
        insights_count = len(service.build_correlation_insights(asset.id))

        for event in events:
            severity_counts[event.severity.value] += 1
        recent_alerts.extend([f"{asset.name}: {a.reason}" for a in alerts])

        asset_rows.append(
            f"<tr><td><a href='/ui/assets/{asset.id}'>{asset.id}</a></td><td>{asset.name}</td><td>{asset.asset_type.value}</td>"
            f"<td>{asset.location or '-'}</td><td>{len(events)}</td><td>{len(alerts)}</td><td>{insights_count}</td></tr>"
        )

    events_total = max(overview_data["events_total"], 1)
    info_pct = int(severity_counts["info"] * 100 / events_total)
    warn_pct = int(severity_counts["warning"] * 100 / events_total)
    crit_pct = max(0, 100 - info_pct - warn_pct)
    trend_points = "30,90 120,45 210,55 300,25 390,35 480,20"

    alerts_html = "".join(f"<li>{alert}</li>" for alert in recent_alerts[:7]) or "<li>No alerts yet</li>"
    rows_html = "".join(asset_rows) if asset_rows else "<tr><td colspan='7'>No assets yet</td></tr>"

    return f"""
    <html>
      <body style='margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#eef2f6;color:#18202a;'>
        <div style='display:flex;min-height:100vh;'>
          <aside style='width:86px;background:#273543;color:#fff;padding:14px 10px;'>
            <div style='font-weight:700;font-size:20px;text-align:center;margin:8px 0 24px;'>IM</div>
            <div style='padding:10px 8px;border-left:3px solid #87d04a;background:#324657;border-radius:4px;margin-bottom:8px;'>Overview</div>
            <div style='padding:10px 8px;opacity:.85;'>Assets</div>
            <div style='padding:10px 8px;opacity:.85;'>Alerts</div>
            <div style='padding:10px 8px;opacity:.85;'>Collectors</div>
          </aside>

          <main style='flex:1;'>
            <header style='background:#374957;color:#fff;padding:14px 22px;display:flex;justify-content:space-between;align-items:center;'>
              <div style='display:flex;gap:20px;font-weight:600;'>
                <span>Dashboard</span><span style='opacity:.8;'>Reports</span><span style='opacity:.8;'>Security</span><span style='opacity:.8;'>Settings</span>
              </div>
              <div style='font-size:14px;opacity:.9;'>InfraMind Monitor</div>
            </header>

            <section style='padding:18px;'>
              <div style='display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:12px;margin-bottom:14px;'>
                <div style='background:#fff;border:1px solid #dbe3ec;padding:14px;border-radius:8px;'><div style='color:#6f7f91;font-size:13px;'>All Events</div><div style='font-size:34px;font-weight:700;'>{overview_data['events_total']}</div><div style='font-size:13px;color:#2f9d44;'>info {severity_counts['info']} · warn {severity_counts['warning']} · crit {severity_counts['critical']}</div></div>
                <div style='background:#fff;border:1px solid #dbe3ec;padding:14px;border-radius:8px;'><div style='color:#6f7f91;font-size:13px;'>Assets</div><div style='font-size:34px;font-weight:700;'>{overview_data['assets_total']}</div><div style='font-size:13px;color:#5b6c7d;'>critical assets: {overview_data['critical_assets']}</div></div>
                <div style='background:#fff;border:1px solid #dbe3ec;padding:14px;border-radius:8px;'><div style='color:#6f7f91;font-size:13px;'>Worker</div><div style='font-size:34px;font-weight:700;'>{'OK' if worker_health_data['running'] else 'DOWN'}</div><div style='font-size:13px;color:#5b6c7d;'>tracked {worker_health_data['tracked']} · failed {worker_health_data['failed']}</div></div>
                <div style='background:#fff;border:1px solid #dbe3ec;padding:14px;border-radius:8px;'><div style='color:#6f7f91;font-size:13px;'>Collectors</div><div style='font-size:34px;font-weight:700;'>{len(service.list_collector_targets())}</div><div style='font-size:13px;color:#5b6c7d;'>cycles {worker_health_data['cycle_count']}</div></div>
              </div>

              <div style='display:grid;grid-template-columns:2fr 1fr;gap:12px;margin-bottom:12px;'>
                <div style='background:#fff;border:1px solid #dbe3ec;border-radius:8px;padding:14px;'>
                  <h3 style='margin:0 0 8px;'>Logs Trend</h3>
                  <svg viewBox='0 0 520 110' style='width:100%;height:140px;background:#f7fbff;border:1px solid #e3ebf3;border-radius:6px;'>
                    <polyline points='{trend_points}' fill='rgba(40,141,205,0.18)' stroke='#1c8ece' stroke-width='3'></polyline>
                  </svg>
                </div>
                <div style='background:#fff;border:1px solid #dbe3ec;border-radius:8px;padding:14px;'>
                  <h3 style='margin:0 0 8px;'>Severity Mix</h3>
                  <div style='height:12px;background:#eaf0f7;border-radius:999px;overflow:hidden;display:flex;'>
                    <div style='width:{info_pct}%;background:#1a8fcf;'></div>
                    <div style='width:{warn_pct}%;background:#f59d1a;'></div>
                    <div style='width:{crit_pct}%;background:#ef4f4f;'></div>
                  </div>
                  <p style='font-size:13px;color:#5b6c7d;'>Info {info_pct}% · Warning {warn_pct}% · Critical {crit_pct}%</p>
                  <p style='margin:0;font-size:13px;' id='worker-health-widget'><b>Worker health:</b> {'running' if worker_health_data['running'] else 'stopped'} · tracked {worker_health_data['tracked']} · failed {worker_health_data['failed']} · cycles {worker_health_data['cycle_count']} · <a href='/worker/health'>Worker health JSON</a> · <a href='/ui/diagnostics'>Diagnostics</a></p>
                </div>
              </div>

              <div style='display:grid;grid-template-columns:2fr 1fr;gap:12px;'>
                <div style='background:#fff;border:1px solid #dbe3ec;border-radius:8px;padding:14px;'>
                  <h3 style='margin:0 0 10px;'>Assets Matrix</h3>
                  <table style='width:100%;border-collapse:collapse;font-size:14px;'>
                    <thead>
                      <tr style='text-align:left;background:#f5f8fc;'>
                        <th style='padding:8px;border-bottom:1px solid #e0e8f0;'>ID</th>
                        <th style='padding:8px;border-bottom:1px solid #e0e8f0;'>Name</th>
                        <th style='padding:8px;border-bottom:1px solid #e0e8f0;'>Type</th>
                        <th style='padding:8px;border-bottom:1px solid #e0e8f0;'>Location</th>
                        <th style='padding:8px;border-bottom:1px solid #e0e8f0;'>Events</th>
                        <th style='padding:8px;border-bottom:1px solid #e0e8f0;'>Alerts</th>
                        <th style='padding:8px;border-bottom:1px solid #e0e8f0;'>Insights</th>
                      </tr>
                    </thead>
                    <tbody>{rows_html}</tbody>
                  </table>
                </div>
                <div style='background:#fff;border:1px solid #dbe3ec;border-radius:8px;padding:14px;'>
                  <h3 style='margin:0 0 10px;'>Recent Alerts</h3>
                  <ul style='margin:0;padding-left:18px;display:grid;gap:8px;font-size:14px;line-height:1.3;'>{alerts_html}</ul>
                  <hr style='border:none;border-top:1px solid #e6edf5;margin:12px 0;'>
                  <div style='display:grid;gap:6px;font-size:13px;'>
                    <a href='/ui/assets'>Manage assets</a>
                    <a href='/ui/events'>Send event</a>
                    <a href='/ui/collectors'>Collector targets</a>
                    <a href='/worker/targets'>Worker targets</a>
                  </div>
                </div>
              </div>
            </section>
          </main>
        </div>
        <script>
          async function refreshWorkerHealthWidget() {{
            try {{
              const resp = await fetch('/worker/health');
              if (!resp.ok) return;
              const payload = await resp.json();
              const widget = document.getElementById('worker-health-widget');
              if (!widget) return;
              const state = payload.running ? 'running' : 'stopped';
              widget.innerHTML = `<b>Worker health:</b> ${{state}} · tracked ${{payload.tracked}} · failed ${{payload.failed}} · cycles ${{payload.cycle_count}} · <a href='/worker/health'>Worker health JSON</a> · <a href='/ui/diagnostics'>Diagnostics</a>`;
            }} catch (_e) {{
              // ignore widget refresh errors to keep dashboard stable
            }}
          }}
          setInterval(refreshWorkerHealthWidget, 5000);
        </script>
      </body>
    </html>
    """


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/overview", response_model=Overview)
def overview() -> Overview:
    return Overview(**service.overview())


@app.get("/assets", response_model=list[Asset])
def list_assets() -> list[Asset]:
    return service.list_assets()


@app.post("/assets", response_model=Asset)
def upsert_asset(asset: Asset) -> Asset:
    return service.upsert_asset(asset)


@app.get("/collectors", response_model=list[CollectorTargetPublic])
def list_collectors() -> list[CollectorTargetPublic]:
    return [CollectorTargetPublic.from_target(t) for t in service.list_collector_targets()]


@app.post("/collectors", response_model=CollectorTarget)
def upsert_collector(target: CollectorTarget) -> CollectorTarget:
    try:
        return service.upsert_collector_target(target)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.delete("/collectors/{target_id}")
def delete_collector(target_id: str) -> dict[str, str]:
    service.delete_collector_target(target_id)
    return {"status": "deleted"}


@app.get("/worker/status")
def worker_status() -> dict:
    status = worker.status()
    status["enabled"] = ENABLE_AGENTLESS_WORKER
    return status


@app.get("/worker/targets")
def worker_targets() -> list[dict]:
    return worker.target_status()


@app.post("/worker/run-once")
def worker_run_once() -> dict[str, int]:
    accepted = worker.run_once()
    return {"accepted": accepted}


@app.post("/events", response_model=Event)
def register_event(event: Event) -> Event:
    try:
        stored, _ = service.register_event(event)
        return stored
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/ingest/events", response_model=IngestSummary)
def register_events_batch(batch: EventBatch) -> IngestSummary:
    try:
        accepted = service.register_events_batch(batch.events)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return IngestSummary(accepted=accepted)


@app.get("/assets/{asset_id}/events", response_model=list[Event])
def list_events(asset_id: str) -> list[Event]:
    if not _asset_exists(asset_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    return service.list_events(asset_id)


@app.get("/assets/{asset_id}/alerts", response_model=list[Alert])
def list_alerts(asset_id: str) -> list[Alert]:
    if not _asset_exists(asset_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    return service.build_alerts(asset_id)


@app.get("/assets/{asset_id}/insights", response_model=list[CorrelationInsight])
def list_insights(asset_id: str) -> list[CorrelationInsight]:
    if not _asset_exists(asset_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    return service.build_correlation_insights(asset_id)


@app.get("/assets/{asset_id}/recommendation", response_model=Recommendation)
def get_recommendation(asset_id: str) -> Recommendation:
    try:
        return service.build_recommendation(asset_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
