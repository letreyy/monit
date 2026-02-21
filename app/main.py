import os
import json
import asyncio
from collections import Counter
from contextlib import asynccontextmanager

from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, StreamingResponse

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

      <script>
        (function() {
          const targetId = encodeURIComponent("{target_id}");
          const collectorType = encodeURIComponent("{collector_type}");
          const hasError = encodeURIComponent("{has_error}");
          const qs = `limit=100&target_id=${targetId}&collector_type=${collectorType}&has_error=${hasError}`;

          async function refreshDiagnostics() {
            try {
              const [sumResp, trendResp] = await Promise.all([
                fetch(`/worker/diagnostics/summary?${qs}`),
                fetch(`/worker/diagnostics/trend?${qs}`),
              ]);
              const summary = await sumResp.json();
              const trend = await trendResp.json();

              const summaryEl = document.getElementById('diag-summary');
              summaryEl.innerHTML = `<b>Summary:</b> runs=${summary.runs}, ok=${summary.ok}, errors=${summary.errors}, accepted_events_sum=${summary.accepted_events_sum}`;

              const barsEl = document.getElementById('diag-bars');
              const byType = summary.by_type || {};
              const keys = Object.keys(byType);
              if (!keys.length) {
                barsEl.innerHTML = '<i>No data for chart</i>';
              } else {
                let maxTotal = 1;
                keys.forEach(k => { const t = (byType[k].ok || 0) + (byType[k].err || 0); if (t > maxTotal) maxTotal = t; });
                barsEl.innerHTML = keys.sort().map(k => {
                  const ok = byType[k].ok || 0;
                  const err = byType[k].err || 0;
                  const width = Math.floor(((ok + err) / maxTotal) * 240);
                  const color = err ? '#d9534f' : '#5cb85c';
                  return `<div><b>${k}</b> ok=${ok} err=${err}<div style='background:#ddd;width:240px;height:12px'><div style='background:${color};width:${width}px;height:12px'></div></div></div>`;
                }).join('');
              }

              const trendEl = document.getElementById('diag-trend');
              const points = (trend.points || []).map((p, i, arr) => {
                const maxVal = Math.max(...arr.map(x => x.accepted_events), 1);
                const x = 10 + i * 14;
                const y = 70 - Math.floor((p.accepted_events / maxVal) * 60);
                return `${x},${y}`;
              });
              if (!points.length) {
                trendEl.innerHTML = '<i>No trend data</i>';
              } else {
                trendEl.innerHTML = `<svg width='760' height='90' style='border:1px solid #ddd;background:#fff'><polyline points='${points.join(' ')}' fill='none' stroke='#337ab7' stroke-width='2' /></svg>`;
              }
            } catch (e) {
              document.getElementById('diag-summary').innerHTML = '<b>Summary:</b> failed to load diagnostics';
            }
          }

          refreshDiagnostics();
          setInterval(refreshDiagnostics, 10000);
        })();
      </script>
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


def _parse_has_error_filter(has_error: str | None) -> bool | None:
    if has_error == "1":
        return True
    if has_error == "0":
        return False
    return None


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


@app.get("/worker/history.csv", response_class=PlainTextResponse)
def worker_history_csv(
    limit: int = 200,
    target_id: str | None = None,
    collector_type: str | None = None,
    has_error: str | None = None,
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


@app.get("/worker/diagnostics/summary")
def worker_diagnostics_summary(
    limit: int = 100,
    target_id: str | None = None,
    collector_type: str | None = None,
    has_error: str | None = None,
) -> dict:
    has_error_value = _parse_has_error_filter(has_error)

    history = worker.history(
        limit=limit,
        target_id=target_id,
        collector_type=collector_type,
        has_error=has_error_value,
    )
    return _build_diagnostics_summary(history)


@app.get("/worker/diagnostics/trend")
def worker_diagnostics_trend(
    limit: int = 100,
    target_id: str | None = None,
    collector_type: str | None = None,
    has_error: str | None = None,
) -> dict:
    has_error_value = _parse_has_error_filter(has_error)

    history = worker.history(
        limit=limit,
        target_id=target_id,
        collector_type=collector_type,
        has_error=has_error_value,
    )
    return _build_diagnostics_trend(history)


@app.get("/worker/diagnostics/stream")
async def worker_diagnostics_stream(
    limit: int = 100,
    target_id: str | None = None,
    collector_type: str | None = None,
    has_error: str | None = None,
    tick_sec: float = 3.0,
    max_events: int | None = None,
) -> StreamingResponse:
    has_error_value = _parse_has_error_filter(has_error)

    async def event_stream():
        sent = 0
        while True:
            history = worker.history(
                limit=limit,
                target_id=target_id,
                collector_type=collector_type,
                has_error=has_error_value,
            )
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
    target_id: str = "",
    collector_type: str = "",
    has_error: str = "",
) -> str:
    has_error_value = _parse_has_error_filter(has_error)

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
    qs = f"limit=100&target_id={target_id}&collector_type={collector_type}&has_error={has_error}"

    return f"""
    <html><body style='font-family: Arial; max-width: 1200px; margin: 2rem auto;'>
      <h1>Worker diagnostics</h1>
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
        <button type='submit'>Apply</button>
      </form>
      <p><a href='/worker/history.csv?target_id={target_id}&collector_type={collector_type}&has_error={has_error}'>Download filtered CSV</a></p>
      <table border='1' cellpadding='8' cellspacing='0'>
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


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> str:
    overview_data = service.overview()
    worker_health_data = _worker_health_snapshot()

    assets = service.list_assets()
    asset_event_counts: dict[str, int] = {}
    all_events = []
    for asset in assets:
        events = service.list_events(asset.id)
        asset_event_counts[asset.id] = len(events)
        all_events.extend(events)

    source_counts = Counter(e.source for e in all_events)
    severity_counts = Counter(e.severity.value for e in all_events)
    total_events = max(len(all_events), 1)

    windows_events = source_counts.get("windows_eventlog", 0)
    syslog_events = source_counts.get("syslog", 0)
    agentless_events = sum(v for k, v in source_counts.items() if k.startswith("agentless_"))

    trend_counts: Counter[str] = Counter()
    for e in all_events:
        month = str(e.timestamp)[:7]
        trend_counts[month] += 1
    trend_labels = sorted(trend_counts.keys())[-6:]
    trend_values = [trend_counts[m] for m in trend_labels]

    def _polyline(values: list[int]) -> str:
        if not values:
            return ""
        max_val = max(values) or 1
        points = []
        for i, v in enumerate(values):
            x = 20 + (i * 90)
            y = 140 - int((v / max_val) * 110)
            points.append(f"{x},{y}")
        return " ".join(points)

    top_assets = sorted(asset_event_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
    top_rows = "".join(
        f"<tr><td>{aid}</td><td>{cnt}</td></tr>" for aid, cnt in top_assets
    ) or "<tr><td colspan='2'>No data</td></tr>"

    recent_alert_candidates = [
        e for e in sorted(all_events, key=lambda x: str(x.timestamp), reverse=True)
        if e.severity.value in ("warning", "critical")
    ][:7]
    recent_alerts_html = "".join(
        f"<div class='alert-item {e.severity.value}'><div class='alert-title'>{e.source}: {e.message[:110]}</div><div class='alert-ts'>{e.timestamp}</div></div>"
        for e in recent_alert_candidates
    ) or "<div class='muted'>No warning/critical events yet.</div>"

    severity_rows = "".join(
        f"<tr><td>{level.title()}</td><td>{severity_counts.get(level, 0)}</td></tr>"
        for level in ["info", "warning", "critical"]
    )

    rows = []
    for asset in assets:
        alerts_count = len(service.build_alerts(asset.id))
        insights_count = len(service.build_correlation_insights(asset.id))
        events_count = asset_event_counts.get(asset.id, 0)
        rows.append(
            f"<tr><td><a href='/ui/assets/{asset.id}'>{asset.id}</a></td><td>{asset.asset_type.value}</td><td>{asset.location or '-'}</td>"
            f"<td>{events_count}</td><td>{alerts_count}</td><td>{insights_count}</td></tr>"
        )
    rows_html = "".join(rows) if rows else "<tr><td colspan='6'>No assets yet</td></tr>"

    win_pct = int((windows_events / total_events) * 100)
    syslog_pct = int((syslog_events / total_events) * 100)
    ag_pct = int((agentless_events / total_events) * 100)
    trend_poly = _polyline(trend_values)
    trend_points = "".join(
        f"<text x='{20 + i * 90}' y='158' font-size='10' fill='#667'>{label[2:]}</text>" for i, label in enumerate(trend_labels)
    )

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
          <a href='/ui/assets'>Assets</a><a href='/ui/events'>Events</a><a href='/ui/collectors'>Collectors</a><a href='/ui/diagnostics'>Diagnostics</a>
        </div>
      </div>
      <div class='container'>
        <h2>Events Overview</h2>
        <div class='cards'>
          <div class='card'><div class='muted'>All Events</div><div class='metric'>{overview_data['events_total']}</div><div class='small'>Across {overview_data['assets_total']} assets</div></div>
          <div class='card'><div class='muted'>Windows Events</div><div class='metric'>{windows_events}</div><div class='small'>{win_pct}% of all events</div></div>
          <div class='card'><div class='muted'>Syslog Events</div><div class='metric'>{syslog_events}</div><div class='small'>{syslog_pct}% of all events</div></div>
          <div class='card' style='display:flex;align-items:center;gap:8px'><div><div class='muted'>Agentless Events</div><div class='metric' style='font-size:30px'>{agentless_events}</div><div class='small'>{ag_pct}% of all events</div></div><div class='ring' style='background:conic-gradient(#0ea5e9 {ag_pct}%, #e2e8f0 0)'></div></div>
        </div>

        <div class='health'>
          <b>Worker health:</b> {'running' if worker_health_data['running'] else 'stopped'} |
          enabled: {worker_health_data['enabled']} | tracked: {worker_health_data['tracked']} |
          failed: {worker_health_data['failed']} | stale: {worker_health_data['stale']} |
          cycles: {worker_health_data['cycle_count']} | <a href='/worker/health'>JSON</a>
        </div>

        <div class='grid'>
          <div class='panel'>
            <h3>Logs Trend</h3>
            <svg width='560' height='170' style='max-width:100%;background:#fff'>
              <line x1='20' y1='140' x2='540' y2='140' stroke='#cbd5e1' stroke-width='1' />
              <polyline points='{trend_poly}' fill='rgba(14,165,233,0.15)' stroke='#0ea5e9' stroke-width='3' />
              {trend_points}
            </svg>
          </div>
          <div class='panel'>
            <h3>Top 5 Assets</h3>
            <table>
              <thead><tr><th>Asset</th><th>Events</th></tr></thead>
              <tbody>{top_rows}</tbody>
            </table>
            <div style='margin-top:16px'>
              <div class='muted'>Severity Distribution</div>
              <table><tbody>{severity_rows}</tbody></table>
            </div>
          </div>
          <div class='panel'>
            <h3>Recent Alerts</h3>
            {recent_alerts_html}
          </div>
        </div>

        <div class='panel' style='margin-top:14px'>
          <h3 style='font-size:20px'>Assets table</h3>
          <table>
            <thead><tr><th>Asset</th><th>Type</th><th>Location</th><th>Events</th><th>Alerts</th><th>Insights</th></tr></thead>
            <tbody>{rows_html}</tbody>
          </table>
        </div>
      </div>
    </body></html>
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
