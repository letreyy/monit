from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    info = "info"
    warning = "warning"
    critical = "critical"


class AssetType(str, Enum):
    server = "server"
    storage_shelf = "storage_shelf"
    network = "network"
    bmc = "bmc"


class Asset(BaseModel):
    id: str = Field(..., description="Unique asset identifier")
    name: str
    asset_type: AssetType
    location: str | None = None


class Event(BaseModel):
    asset_id: str
    source: str = Field(..., description="linux, idrac, snmp, etc")
    message: str
    metric: str | None = None
    value: float | None = None
    severity: Severity = Severity.info
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class EventBatch(BaseModel):
    events: list[Event]


class IngestSummary(BaseModel):
    accepted: int


class Recommendation(BaseModel):
    asset_id: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    summary: str
    actions: list[str]
