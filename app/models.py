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
    winrm_transport: str = "ntlm"
    winrm_use_https: bool = False
    winrm_validate_tls: bool = False
    winrm_event_logs: str = "System,Application"
    winrm_batch_size: int = Field(default=50, ge=1, le=500)
    ssh_metrics_command: str = "cat /proc/loadavg"
    ssh_log_path: str = "/var/log/syslog"
    ssh_tail_lines: int = Field(default=50, ge=1, le=500)
    snmp_community: str = "public"
    snmp_version: str = "2c"
    snmp_oids: str = "1.3.6.1.2.1.1.3.0,1.3.6.1.2.1.1.5.0"


class CollectorTargetPublic(BaseModel):
    id: str
    name: str
    address: str
    collector_type: CollectorType
    port: int
    username: str
    password: str = "********"
    poll_interval_sec: int
    enabled: bool
    asset_id: str
    winrm_transport: str
    winrm_use_https: bool
    winrm_validate_tls: bool
    winrm_event_logs: str
    winrm_batch_size: int
    ssh_metrics_command: str
    ssh_log_path: str
    ssh_tail_lines: int
    snmp_community: str = "********"
    snmp_version: str
    snmp_oids: str

    @classmethod
    def from_target(cls, target: "CollectorTarget") -> "CollectorTargetPublic":
        return cls(**target.model_dump(exclude={"password", "snmp_community"}), password="********", snmp_community="********")


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


class LogCluster(BaseModel):
    cluster_id: str
    source: str
    signature: str
    example_message: str
    events_count: int = Field(..., ge=1)
    share: float = Field(..., ge=0.0, le=1.0)
    severity_mix: dict[str, int]


class LogAnomaly(BaseModel):
    kind: str
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str
    evidence: list[str] = Field(default_factory=list)
    related_cluster_id: str | None = None
    related_metric: str | None = None


class LogAnalyticsInsight(BaseModel):
    asset_id: str
    analyzed_events: int = Field(..., ge=0)
    clusters: list[LogCluster]
    anomalies: list[LogAnomaly]
    summary: list[str]


class PolicyMergeStrategy(str, Enum):
    union = "union"
    intersection = "intersection"


class LogAnalyticsPolicy(BaseModel):
    id: str
    name: str
    tenant_id: str | None = None
    ignore_sources: list[str] = Field(default_factory=list)
    ignore_signatures: list[str] = Field(default_factory=list)
    enabled: bool = True


class LogAnalyticsPolicyAuditEntry(BaseModel):
    ts: int
    policy_id: str
    tenant_id: str | None = None
    action: str
    actor_role: str
    details: str = ""




class LogAnalyticsDryRunImpact(BaseModel):
    source: str
    signature: str
    cluster_id: str
    events_filtered: int = Field(..., ge=1)
    severity_mix: dict[str, int] = Field(default_factory=dict)
    impact_score: float = Field(0.0, ge=0.0)



class LogAnalyticsPolicyAuditDetails(BaseModel):
    schema_version: int = 1
    action: str
    changed_fields: list[str] = Field(default_factory=list)
    before: dict[str, object] | None = None
    after: dict[str, object] | None = None


class LogAnalyticsPolicyAuditEntryParsed(BaseModel):
    ts: int
    policy_id: str
    tenant_id: str | None = None
    action: str
    actor_role: str
    details: str = ""
    details_json: LogAnalyticsPolicyAuditDetails | None = None

class LogAnalyticsPolicyDryRun(BaseModel):
    asset_id: str
    total_events: int = Field(..., ge=0)
    filtered_events: int = Field(..., ge=0)
    remaining_events: int = Field(..., ge=0)
    filtered_share: float = Field(0.0, ge=0.0, le=1.0)
    remaining_share: float = Field(0.0, ge=0.0, le=1.0)
    applied_sources: list[str] = Field(default_factory=list)
    applied_signatures: list[str] = Field(default_factory=list)
    top_impacted_clusters: list[LogAnalyticsDryRunImpact] = Field(default_factory=list)
    impact_mode: str = "weighted"


class LogAnalyticsAssetSummary(BaseModel):
    asset_id: str
    analyzed_events: int = Field(..., ge=0)
    anomalies_total: int = Field(..., ge=0)
    top_severity: Severity | None = None
    top_reason: str | None = None


class LogAnalyticsOverview(BaseModel):
    assets_considered: int = Field(..., ge=0)
    assets_with_anomalies: int = Field(..., ge=0)
    total_anomalies: int = Field(..., ge=0)
    by_kind: dict[str, int]
    by_severity: dict[str, int]
    assets: list[LogAnalyticsAssetSummary]


class RunbookHint(BaseModel):
    title: str
    rationale: str
    action: str
    confidence: float = Field(0.0, ge=0.0, le=1.0)


class LogAnalyticsRunbookHints(BaseModel):
    asset_id: str
    hints: list[RunbookHint] = Field(default_factory=list)


class WorkerHistoryEntry(BaseModel):
    ts: str
    target_id: str
    collector_type: str
    accepted_events: int
    last_error: str | None = None
    failure_streak: int = 0
    last_cursor: str | None = None


class AccessAuditEntry(BaseModel):
    ts: int
    path: str
    role: str
    action: str
    result: str
