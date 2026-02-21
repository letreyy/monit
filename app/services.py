import re

from app.models import (
    AccessAuditEntry,
    Alert,
    Asset,
    CollectorState,
    CollectorTarget,
    CorrelationInsight,
    Event,
    Recommendation,
    Severity,
    WorkerHistoryEntry,
)
from app.storage import SQLiteStorage


class MonitoringService:
    def __init__(self, storage: SQLiteStorage | None = None) -> None:
        self.storage = storage or SQLiteStorage()

    def upsert_asset(self, asset: Asset) -> Asset:
        return self.storage.upsert_asset(asset)

    def delete_asset(self, asset_id: str) -> None:
        self.storage.delete_asset(asset_id)

    def list_assets(self) -> list[Asset]:
        return self.storage.list_assets()

    def upsert_collector_target(self, target: CollectorTarget) -> CollectorTarget:
        if not self.storage.asset_exists(target.asset_id):
            raise KeyError(f"Unknown asset '{target.asset_id}'")
        return self.storage.upsert_collector_target(target)

    def list_collector_targets(self) -> list[CollectorTarget]:
        return self.storage.list_collector_targets()

    def delete_collector_target(self, target_id: str) -> None:
        self.storage.delete_collector_target(target_id)

    def get_collector_state(self, target_id: str) -> CollectorState:
        return self.storage.get_collector_state(target_id)

    def upsert_collector_state(self, state: CollectorState) -> CollectorState:
        return self.storage.upsert_collector_state(state)


    def add_worker_history(self, entry: WorkerHistoryEntry) -> WorkerHistoryEntry:
        return self.storage.insert_worker_history(entry)

    def list_worker_history(
        self,
        limit: int = 100,
        target_id: str | None = None,
        collector_type: str | None = None,
        has_error: bool | None = None,
    ) -> list[WorkerHistoryEntry]:
        return self.storage.list_worker_history(
            limit=limit,
            target_id=target_id,
            collector_type=collector_type,
            has_error=has_error,
        )


    def add_access_audit(self, entry: AccessAuditEntry) -> AccessAuditEntry:
        return self.storage.insert_access_audit(entry)

    def list_access_audit(self, limit: int = 100) -> list[AccessAuditEntry]:
        return self.storage.list_access_audit(limit=limit)

    def delete_access_audit_older_than(self, min_ts: int) -> int:
        return self.storage.delete_access_audit_older_than(min_ts=min_ts)

    def delete_worker_history_older_than(self, min_ts_iso: str) -> int:
        return self.storage.delete_worker_history_older_than(min_ts_iso=min_ts_iso)

    def register_event(self, event: Event) -> tuple[Event, bool]:
        if not self.storage.asset_exists(event.asset_id):
            raise KeyError(f"Unknown asset '{event.asset_id}'")
        return self.storage.insert_event(event)

    def register_events_batch(self, events: list[Event]) -> int:
        accepted = 0
        for event in events:
            _, inserted = self.register_event(event)
            if inserted:
                accepted += 1
        return accepted

    def list_events(self, asset_id: str, limit: int = 1000) -> list[Event]:
        return self.storage.list_events(asset_id, limit=limit)

    def build_alerts(self, asset_id: str) -> list[Alert]:
        events = self.list_events(asset_id)
        alerts: list[Alert] = []

        if any(e.metric == "iowait" and (e.value or 0) >= 25 for e in events):
            alerts.append(Alert(asset_id=asset_id, severity=Severity.warning, reason="High iowait"))

        if any("thermal" in e.message.lower() for e in events):
            alerts.append(Alert(asset_id=asset_id, severity=Severity.critical, reason="Thermal warning"))

        if any("smart" in e.message.lower() for e in events):
            alerts.append(Alert(asset_id=asset_id, severity=Severity.critical, reason="SMART degradation"))

        return alerts

    def build_correlation_insights(self, asset_id: str) -> list[CorrelationInsight]:
        events = self.list_events(asset_id)
        insights: list[CorrelationInsight] = []

        win_events = [e for e in events if e.source == "windows_eventlog"]
        messages = [e.message.lower() for e in win_events]

        shutdown_matches = sum(1 for m in messages if "eventid=6008" in m or "eventid=41" in m)
        if shutdown_matches >= 2:
            insights.append(
                CorrelationInsight(
                    asset_id=asset_id,
                    title="Repeated unexpected shutdown pattern",
                    confidence=0.87,
                    evidence_count=shutdown_matches,
                    recommendation="Проверить питание/UPS и журнал Kernel-Power; выполнить hardware diagnostics.",
                )
            )

        logon_failures = sum(1 for m in messages if "eventid=4625" in m)
        if logon_failures >= 5:
            insights.append(
                CorrelationInsight(
                    asset_id=asset_id,
                    title="Burst of failed logons",
                    confidence=0.78,
                    evidence_count=logon_failures,
                    recommendation="Проверить источник попыток входа, включить блокировки и ограничить RDP/SMB доступ.",
                )
            )

        disk_errors = sum(1 for m in messages if re.search(r"eventid=(7|51|55|153)", m))
        if disk_errors >= 3:
            insights.append(
                CorrelationInsight(
                    asset_id=asset_id,
                    title="Windows storage error cluster",
                    confidence=0.81,
                    evidence_count=disk_errors,
                    recommendation="Проверить контроллер/кабели/диск, запустить chkdsk и диагностику storage path.",
                )
            )

        return insights

    def build_recommendation(self, asset_id: str) -> Recommendation:
        if not self.storage.asset_exists(asset_id):
            raise KeyError(f"Unknown asset '{asset_id}'")

        events = self.list_events(asset_id)
        if not events:
            return Recommendation(
                asset_id=asset_id,
                risk_score=0.05,
                summary="Инцидентов не обнаружено. Наблюдение в штатном режиме.",
                actions=["Продолжать мониторинг", "Проверять тренды раз в сутки"],
            )

        risk = 0.1
        actions: list[str] = []
        critical_count = sum(1 for e in events if e.severity == Severity.critical)
        warning_count = sum(1 for e in events if e.severity == Severity.warning)
        risk += min(critical_count * 0.2, 0.5)
        risk += min(warning_count * 0.05, 0.2)

        for alert in self.build_alerts(asset_id):
            if alert.reason == "High iowait":
                risk += 0.2
                actions.append("Высокий iowait: проверить очередь контроллера и latency LUN.")
            elif alert.reason == "Thermal warning":
                risk += 0.15
                actions.append("Thermal-события: проверить охлаждение и airflow.")
            elif alert.reason == "SMART degradation":
                risk += 0.2
                actions.append("SMART-деградация: подготовить замену диска.")

        insights = self.build_correlation_insights(asset_id)
        if insights:
            risk += min(len(insights) * 0.08, 0.2)
            for insight in insights:
                actions.append(f"Correlation: {insight.title} ({insight.evidence_count} events)")

        if not actions:
            actions.append("Проверить runbook и пороги алертинга.")

        risk = min(risk, 0.99)
        summary = (
            "Высокий риск деградации. Требуется приоритезированное вмешательство."
            if risk >= 0.75
            else "Умеренный риск. Рекомендуется плановая оптимизация и диагностика."
            if risk >= 0.4
            else "Низкий риск. Продолжать наблюдение и базовую профилактику."
        )

        return Recommendation(asset_id=asset_id, risk_score=round(risk, 2), summary=summary, actions=actions)

    def overview(self) -> dict[str, int]:
        assets = self.list_assets()
        critical_assets = 0
        events_total = 0

        for asset in assets:
            events = self.list_events(asset.id)
            events_total += len(events)
            if any(e.severity == Severity.critical for e in events):
                critical_assets += 1

        return {
            "assets_total": len(assets),
            "events_total": events_total,
            "critical_assets": critical_assets,
        }
