from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from app.models import (
    Alert,
    Asset,
    AssetType,
    CorrelationInsight,
    Event,
    EventBatch,
    IngestSummary,
    Overview,
    Recommendation,
    Severity,
)
from app.services import MonitoringService

app = FastAPI(title="InfraMind Monitor API", version="0.7.0")
service = MonitoringService()


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
        <li><a href='/docs'>Swagger UI</a></li>
        <li><a href='/redoc'>ReDoc</a></li>
      </ul>
      <p>Now you can manage assets/events via web forms, not only API.</p>
    </body></html>
    """


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


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> str:
    overview_data = service.overview()
    rows = []
    for asset in service.list_assets():
        alerts_count = len(service.build_alerts(asset.id))
        insights_count = len(service.build_correlation_insights(asset.id))
        events_count = len(service.list_events(asset.id))
        rows.append(
            f"<tr><td><a href='/ui/assets/{asset.id}'>{asset.id}</a></td><td>{asset.asset_type.value}</td><td>{asset.location or '-'}</td>"
            f"<td>{events_count}</td><td>{alerts_count}</td><td>{insights_count}</td></tr>"
        )

    rows_html = "".join(rows) if rows else "<tr><td colspan='6'>No assets yet</td></tr>"
    return f"""
    <html><body style='font-family: Arial; max-width: 1100px; margin: 2rem auto;'>
      <h1>InfraMind Dashboard</h1>
      <p><a href='/ui/assets'>Add/List assets</a> | <a href='/ui/events'>Add event</a></p>
      <p>Assets: <b>{overview_data['assets_total']}</b> | Events: <b>{overview_data['events_total']}</b> |
      Critical assets: <b>{overview_data['critical_assets']}</b></p>
      <table border='1' cellpadding='8' cellspacing='0'>
        <thead><tr><th>Asset</th><th>Type</th><th>Location</th><th>Events</th><th>Alerts</th><th>Insights</th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
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


@app.post("/events", response_model=Event)
def register_event(event: Event) -> Event:
    try:
        return service.register_event(event)
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
