from collections import defaultdict

from app.models import Asset, Event, Recommendation, Severity


class MonitoringService:
    def __init__(self) -> None:
        self.assets: dict[str, Asset] = {}
        self.events: dict[str, list[Event]] = defaultdict(list)

    def upsert_asset(self, asset: Asset) -> Asset:
        self.assets[asset.id] = asset
        return asset

    def register_event(self, event: Event) -> Event:
        if event.asset_id not in self.assets:
            raise KeyError(f"Unknown asset '{event.asset_id}'")

        self.events[event.asset_id].append(event)
        return event

    def register_events_batch(self, events: list[Event]) -> int:
        accepted = 0
        for event in events:
            self.register_event(event)
            accepted += 1
        return accepted

    def list_events(self, asset_id: str) -> list[Event]:
        return self.events.get(asset_id, [])

    def build_recommendation(self, asset_id: str) -> Recommendation:
        if asset_id not in self.assets:
            raise KeyError(f"Unknown asset '{asset_id}'")

        events = self.events.get(asset_id, [])

        if not events:
            return Recommendation(
                asset_id=asset_id,
                risk_score=0.05,
                summary="Инцидентов не обнаружено. Наблюдение в штатном режиме.",
                actions=["Продолжать мониторинг", "Проверять тренды раз в сутки"],
            )

        risk = 0.1
        actions: list[str] = []
        io_wait_peak = max(
            (e.value for e in events if e.metric == "iowait" and e.value is not None),
            default=0.0,
        )

        critical_count = sum(1 for e in events if e.severity == Severity.critical)
        warning_count = sum(1 for e in events if e.severity == Severity.warning)

        risk += min(critical_count * 0.2, 0.5)
        risk += min(warning_count * 0.05, 0.2)

        if io_wait_peak >= 25:
            risk += 0.2
            actions.append(
                "Высокий iowait: проверить очередь дискового контроллера и latency LUN."
            )

        if any("thermal" in e.message.lower() for e in events):
            risk += 0.15
            actions.append(
                "Зафиксированы thermal-события: проверить охлаждение, airflow и фильтры."
            )

        if any("smart" in e.message.lower() for e in events):
            risk += 0.2
            actions.append(
                "Есть SMART-предупреждения: подготовить замену диска в ближайшее окно."
            )

        if not actions:
            actions.append("Проверить runbook и подтвердить корректность порогов алертинга.")

        risk = min(risk, 0.99)

        if risk >= 0.75:
            summary = "Высокий риск деградации. Требуется приоритезированное вмешательство."
        elif risk >= 0.4:
            summary = "Умеренный риск. Рекомендуется плановая оптимизация и диагностика."
        else:
            summary = "Низкий риск. Продолжать наблюдение и базовую профилактику."

        return Recommendation(
            asset_id=asset_id,
            risk_score=round(risk, 2),
            summary=summary,
            actions=actions,
        )
