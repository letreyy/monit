from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from app.models import Alert, Asset, Event, EventBatch, IngestSummary, Overview, Recommendation
from app.services import MonitoringService

app = FastAPI(title="InfraMind Monitor API", version="0.4.0")
service = MonitoringService()


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return """
    <html><body style='font-family: Arial; max-width: 860px; margin: 2rem auto;'>
      <h1>InfraMind Monitor</h1>
      <ul>
        <li><a href='/docs'>Swagger UI</a></li>
        <li><a href='/redoc'>ReDoc</a></li>
        <li><a href='/dashboard'>Dashboard</a></li>
      </ul>
      <p>New: Windows Event Log collector script: <code>scripts/windows_eventlog_agent.ps1</code>.</p>
    </body></html>
    """


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> str:
    overview_data = service.overview()
    rows = []
    for asset in service.list_assets():
        alerts_count = len(service.build_alerts(asset.id))
        events_count = len(service.list_events(asset.id))
        rows.append(
            f"<tr><td>{asset.id}</td><td>{asset.asset_type.value}</td><td>{asset.location or '-'}</td>"
            f"<td>{events_count}</td><td>{alerts_count}</td></tr>"
        )

    rows_html = "".join(rows) if rows else "<tr><td colspan='5'>No assets yet</td></tr>"
    return f"""
    <html><body style='font-family: Arial; max-width: 1100px; margin: 2rem auto;'>
      <h1>InfraMind Dashboard</h1>
      <p>Assets: <b>{overview_data['assets_total']}</b> | Events: <b>{overview_data['events_total']}</b> |
      Critical assets: <b>{overview_data['critical_assets']}</b></p>
      <table border='1' cellpadding='8' cellspacing='0'>
        <thead><tr><th>Asset</th><th>Type</th><th>Location</th><th>Events</th><th>Alerts</th></tr></thead>
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
    if not any(a.id == asset_id for a in service.list_assets()):
        raise HTTPException(status_code=404, detail="Asset not found")
    return service.list_events(asset_id)


@app.get("/assets/{asset_id}/alerts", response_model=list[Alert])
def list_alerts(asset_id: str) -> list[Alert]:
    if not any(a.id == asset_id for a in service.list_assets()):
        raise HTTPException(status_code=404, detail="Asset not found")
    return service.build_alerts(asset_id)


@app.get("/assets/{asset_id}/recommendation", response_model=Recommendation)
def get_recommendation(asset_id: str) -> Recommendation:
    try:
        return service.build_recommendation(asset_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
