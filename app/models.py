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


class CollectorType(str, Enum):
    winrm = "winrm"
    ssh = "ssh"
    snmp = "snmp"


class Asset(BaseModel):
    id: str = Field(..., description="Unique asset identifier")
    name: str
    asset_type: AssetType
    location: str | None = None


class CollectorTarget(BaseModel):
    id: str
    name: str
    address: str
    collector_type: CollectorType
    port: int
    username: str
    password: str
    poll_interval_sec: int = Field(default=60, ge=10)
    enabled: bool = True
    asset_id: str


class CollectorState(BaseModel):
    target_id: str
    last_success_ts: str | None = None
    last_run_ts: str | None = None
    last_error: str | None = None
    last_cursor: str | None = None
    failure_streak: int = 0


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


class Alert(BaseModel):
    asset_id: str
    severity: Severity
    reason: str


class Overview(BaseModel):
    assets_total: int
    events_total: int
    critical_assets: int


class CorrelationInsight(BaseModel):
    asset_id: str
    title: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_count: int = Field(..., ge=1)
    recommendation: str
