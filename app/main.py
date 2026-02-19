from fastapi import FastAPI, HTTPException

from app.models import Asset, Event, Recommendation
from app.services import MonitoringService

app = FastAPI(title="InfraMind Monitor API", version="0.1.0")
service = MonitoringService()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/assets", response_model=Asset)
def upsert_asset(asset: Asset) -> Asset:
    return service.upsert_asset(asset)


@app.post("/events", response_model=Event)
def register_event(event: Event) -> Event:
    try:
        return service.register_event(event)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/assets/{asset_id}/events", response_model=list[Event])
def list_events(asset_id: str) -> list[Event]:
    if asset_id not in service.assets:
        raise HTTPException(status_code=404, detail="Asset not found")
    return service.list_events(asset_id)


@app.get("/assets/{asset_id}/recommendation", response_model=Recommendation)
def get_recommendation(asset_id: str) -> Recommendation:
    try:
        return service.build_recommendation(asset_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
