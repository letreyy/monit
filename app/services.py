import hashlib
import re
import statistics
from collections import Counter, defaultdict

from app.models import (
    AccessAuditEntry,
    Alert,
    Asset,
    CollectorState,
    CollectorTarget,
    CorrelationInsight,
    Event,
    LogAnalyticsAssetSummary,
    LogAnalyticsInsight,
    LogAnalyticsOverview,
    LogAnalyticsPolicy,
    LogAnalyticsPolicyAuditEntry,
    LogAnalyticsPolicyDryRun,
    LogAnalyticsDryRunImpact,
    PolicyMergeStrategy,
    LogAnomaly,
    LogCluster,
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

    def delete_ai_log_policy_audit_older_than(self, min_ts: int) -> int:
        return self.storage.delete_ai_log_policy_audit_older_than(min_ts=min_ts)

    def delete_worker_history_older_than(self, min_ts_iso: str) -> int:
        return self.storage.delete_worker_history_older_than(min_ts_iso=min_ts_iso)



    def add_ai_log_policy_audit(self, entry: LogAnalyticsPolicyAuditEntry) -> LogAnalyticsPolicyAuditEntry:
        return self.storage.insert_ai_log_policy_audit(entry)

    def count_ai_log_policy_audit(
        self,
        tenant_id: str | None = None,
        action: str | None = None,
        policy_id: str | None = None,
        min_ts: int | None = None,
        max_ts: int | None = None,
    ) -> int:
        return self.storage.count_ai_log_policy_audit(
            tenant_id=tenant_id,
            action=action,
            policy_id=policy_id,
            min_ts=min_ts,
            max_ts=max_ts,
        )

    def list_ai_log_policy_audit(
        self,
        limit: int = 100,
        tenant_id: str | None = None,
        action: str | None = None,
        policy_id: str | None = None,
        min_ts: int | None = None,
        max_ts: int | None = None,
        sort: str = "desc",
        offset: int = 0,
    ) -> list[LogAnalyticsPolicyAuditEntry]:
        return self.storage.list_ai_log_policy_audit(
            limit=limit,
            tenant_id=tenant_id,
            action=action,
            policy_id=policy_id,
            min_ts=min_ts,
            max_ts=max_ts,
            sort=sort,
            offset=offset,
        )

    def upsert_ai_log_policy(self, policy: LogAnalyticsPolicy) -> LogAnalyticsPolicy:
        return self.storage.upsert_ai_log_policy(policy)

    def list_ai_log_policies(self, enabled_only: bool = False, tenant_id: str | None = None) -> list[LogAnalyticsPolicy]:
        return self.storage.list_ai_log_policies(enabled_only=enabled_only, tenant_id=tenant_id)

    def get_ai_log_policy(self, policy_id: str, tenant_id: str | None = None) -> LogAnalyticsPolicy:
        policy = self.storage.get_ai_log_policy(policy_id, tenant_id=tenant_id)
        if policy is None:
            raise KeyError(f"Unknown ai-log policy '{policy_id}'")
        return policy

    def delete_ai_log_policy(self, policy_id: str, tenant_id: str | None = None) -> None:
        deleted = self.storage.delete_ai_log_policy(policy_id, tenant_id=tenant_id)
        if deleted == 0:
            raise KeyError(f"Unknown ai-log policy '{policy_id}'")

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

    @staticmethod
    def _message_signature(message: str) -> str:
        normalized = message.lower()
        normalized = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", normalized)
        normalized = re.sub(r"\b0x[0-9a-f]+\b", "<hex>", normalized)
        normalized = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<guid>", normalized)
        normalized = re.sub(r"\b\d+\b", "<num>", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized[:200]

    @staticmethod
    def _cluster_id(source: str, signature: str) -> str:
        source_part = re.sub(r"[^a-z0-9]", "", source.lower())[:6] or "src"
        hash_part = hashlib.sha1(f"{source}|{signature}".encode("utf-8")).hexdigest()[:8]
        return f"cl-{source_part}-{hash_part}"


    def resolve_ai_log_filters(
        self,
        ignore_sources: set[str] | None = None,
        ignore_signatures: set[str] | None = None,
        policy_id: str | None = None,
        policy_ids: list[str] | None = None,
        merge_strategy: PolicyMergeStrategy | str = PolicyMergeStrategy.union,
        tenant_id: str | None = None,
    ) -> tuple[set[str], set[str]]:
        merged_sources = set(ignore_sources or set())
        merged_signatures = set(ignore_signatures or set())

        selected_policy_ids: list[str] = []
        if policy_id:
            selected_policy_ids.append(policy_id)
        if policy_ids:
            selected_policy_ids.extend([item for item in policy_ids if item])

        policies: list[LogAnalyticsPolicy] = []
        for pid in selected_policy_ids:
            policy = self.get_ai_log_policy(pid, tenant_id=tenant_id)
            if policy.enabled:
                policies.append(policy)

        if policies:
            strategy = merge_strategy.value if isinstance(merge_strategy, PolicyMergeStrategy) else str(merge_strategy).strip().lower()
            if strategy not in {"union", "intersection"}:
                raise ValueError("Unknown merge_strategy. Allowed values: union, intersection")

            if strategy == "union":
                policy_sources: set[str] = set()
                policy_signatures: set[str] = set()
                for policy in policies:
                    policy_sources.update(policy.ignore_sources)
                    policy_signatures.update(policy.ignore_signatures)
            else:
                policy_sources = set(policies[0].ignore_sources)
                policy_signatures = set(policies[0].ignore_signatures)
                for policy in policies[1:]:
                    policy_sources.intersection_update(policy.ignore_sources)
                    policy_signatures.intersection_update(policy.ignore_signatures)

            merged_sources.update(policy_sources)
            merged_signatures.update(policy_signatures)

        return merged_sources, merged_signatures


    def preview_ai_log_policy_effect(
        self,
        asset_id: str,
        ignore_sources: set[str] | None = None,
        ignore_signatures: set[str] | None = None,
        policy_id: str | None = None,
        policy_ids: list[str] | None = None,
        merge_strategy: PolicyMergeStrategy | str = PolicyMergeStrategy.union,
        limit: int = 300,
        tenant_id: str | None = None,
    ) -> LogAnalyticsPolicyDryRun:
        if not self.storage.asset_exists(asset_id):
            raise KeyError(f"Unknown asset '{asset_id}'")

        resolved_sources, resolved_signatures = self.resolve_ai_log_filters(
            ignore_sources=ignore_sources,
            ignore_signatures=ignore_signatures,
            policy_id=policy_id,
            policy_ids=policy_ids,
            merge_strategy=merge_strategy,
            tenant_id=tenant_id,
        )

        events = list(reversed(self.list_events(asset_id, limit=limit)))
        filtered = 0
        impacted_counter: Counter[tuple[str, str]] = Counter()
        impacted_severity: defaultdict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        for event in events:
            signature = self._message_signature(event.message)
            if event.source.lower() in resolved_sources or signature in resolved_signatures:
                filtered += 1
                key = (event.source, signature)
                impacted_counter[key] += 1
                impacted_severity[key][event.severity.value] += 1

        top_impacted = sorted(
            impacted_counter.items(),
            key=lambda item: (item[1], item[0][0], item[0][1]),
            reverse=True,
        )[:10]

        total = len(events)
        remaining = max(0, total - filtered)
        filtered_share = round((filtered / total), 3) if total else 0.0
        remaining_share = round((remaining / total), 3) if total else 0.0
        return LogAnalyticsPolicyDryRun(
            asset_id=asset_id,
            total_events=total,
            filtered_events=filtered,
            remaining_events=remaining,
            filtered_share=filtered_share,
            remaining_share=remaining_share,
            applied_sources=sorted(resolved_sources),
            applied_signatures=sorted(resolved_signatures),
            top_impacted_clusters=[
                LogAnalyticsDryRunImpact(
                    source=source,
                    signature=signature,
                    cluster_id=self._cluster_id(source, signature),
                    events_filtered=count,
                    severity_mix=dict(impacted_severity[(source, signature)]),
                )
                for (source, signature), count in top_impacted
            ],
        )

    def build_log_analytics(
        self,
        asset_id: str,
        limit: int = 300,
        max_clusters: int = 30,
        max_anomalies: int = 20,
        ignore_sources: set[str] | None = None,
        ignore_signatures: set[str] | None = None,
    ) -> LogAnalyticsInsight:
        if not self.storage.asset_exists(asset_id):
            raise KeyError(f"Unknown asset '{asset_id}'")

        ignore_sources = {item.strip().lower() for item in (ignore_sources or set()) if item.strip()}
        ignore_signatures = {item.strip().lower() for item in (ignore_signatures or set()) if item.strip()}

        events = self.list_events(asset_id, limit=limit)
        if not events:
            return LogAnalyticsInsight(
                asset_id=asset_id,
                analyzed_events=0,
                clusters=[],
                anomalies=[],
                summary=["Недостаточно данных для анализа логов."],
            )

        ordered_events = list(reversed(events))
        total_before_filters = len(ordered_events)
        filtered_events: list[Event] = []
        filtered_out = 0
        for event in ordered_events:
            signature = self._message_signature(event.message)
            if event.source.lower() in ignore_sources or signature in ignore_signatures:
                filtered_out += 1
                continue
            filtered_events.append(event)

        if not filtered_events:
            return LogAnalyticsInsight(
                asset_id=asset_id,
                analyzed_events=0,
                clusters=[],
                anomalies=[],
                summary=[
                    f"Все события отфильтрованы ignore-правилами (исключено {filtered_out} из {total_before_filters}).",
                ],
            )

        total = len(filtered_events)
        grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for event in filtered_events:
            signature = self._message_signature(event.message)
            grouped[(event.source, signature)].append(event)

        cluster_pairs = sorted(grouped.items(), key=lambda item: len(item[1]), reverse=True)
        clusters: list[LogCluster] = []
        for (source, signature), rows in cluster_pairs[:max_clusters]:
            severity_mix = dict(Counter(e.severity.value for e in rows))
            clusters.append(
                LogCluster(
                    cluster_id=self._cluster_id(source, signature),
                    source=source,
                    signature=signature,
                    example_message=rows[0].message,
                    events_count=len(rows),
                    share=round(len(rows) / total, 3),
                    severity_mix=severity_mix,
                )
            )

        cluster_lookup = {(cluster.source, cluster.signature): cluster for cluster in clusters}
        anomalies: list[LogAnomaly] = []
        seen_anomaly_keys: set[tuple[str, str | None, str | None]] = set()
        suspicious_words = ("error", "fail", "timeout", "panic", "denied", "refused", "critical")
        rare_threshold_count = max(1, int(total * 0.05))

        for (source, signature), rows in grouped.items():
            cluster = cluster_lookup.get((source, signature))
            if cluster is None:
                continue
            count = len(rows)
            if count <= rare_threshold_count:
                sample = rows[0].message.lower()
                has_critical = any(e.severity == Severity.critical for e in rows)
                has_suspicious_word = any(word in sample for word in suspicious_words)
                if has_critical or has_suspicious_word:
                    severity = Severity.warning if not has_critical else Severity.critical
                    anomaly_key = ("rare_pattern", cluster.cluster_id, None)
                    if anomaly_key in seen_anomaly_keys:
                        continue
                    seen_anomaly_keys.add(anomaly_key)
                    anomalies.append(
                        LogAnomaly(
                            kind="rare_pattern",
                            severity=severity,
                            confidence=0.72 if not has_critical else 0.84,
                            reason="Редкий паттерн логов с признаками ошибки.",
                            evidence=[
                                f"Правило: count <= {rare_threshold_count} (5% от окна).",
                                f"Кластер {cluster.cluster_id}: {count} из {total} событий.",
                                f"Пример: {rows[0].message[:180]}",
                            ],
                            related_cluster_id=cluster.cluster_id,
                        )
                    )

        recent_window = min(max(10, total // 3), total)
        if total > recent_window:
            older = filtered_events[:-recent_window]
            recent = filtered_events[-recent_window:]
            older_counts: Counter[tuple[str, str]] = Counter((e.source, self._message_signature(e.message)) for e in older)
            recent_counts: Counter[tuple[str, str]] = Counter((e.source, self._message_signature(e.message)) for e in recent)
            older_hour_totals: Counter[int] = Counter(e.timestamp.hour for e in older)
            older_hour_cluster_counts: Counter[tuple[int, tuple[str, str]]] = Counter(
                (e.timestamp.hour, (e.source, self._message_signature(e.message))) for e in older
            )

            for key, recent_count in recent_counts.items():
                cluster = cluster_lookup.get(key)
                if cluster is None:
                    continue
                older_count = older_counts.get(key, 0)
                recent_rate = recent_count / len(recent)
                older_rate = older_count / len(older) if older else 0.0

                recent_rows_for_key = [e for e in recent if (e.source, self._message_signature(e.message)) == key]
                recent_hour = recent_rows_for_key[-1].timestamp.hour if recent_rows_for_key else None
                hourly_baseline_rate = older_rate
                if recent_hour is not None and older_hour_totals.get(recent_hour, 0) > 0:
                    hour_cluster_count = older_hour_cluster_counts.get((recent_hour, key), 0)
                    hourly_baseline_rate = hour_cluster_count / older_hour_totals[recent_hour]

                has_critical = cluster.severity_mix.get(Severity.critical.value, 0) > 0
                if recent_count >= 3 and recent_rate >= 0.4 and older_rate <= 0.2 and hourly_baseline_rate <= 0.15:
                    anomaly_key = ("burst_pattern", cluster.cluster_id, None)
                    if anomaly_key in seen_anomaly_keys:
                        continue
                    seen_anomaly_keys.add(anomaly_key)
                    anomalies.append(
                        LogAnomaly(
                            kind="burst_pattern",
                            severity=Severity.critical if has_critical else Severity.warning,
                            confidence=0.86 if has_critical else 0.8,
                            reason="В последних событиях обнаружен всплеск повторяющегося паттерна.",
                            evidence=[
                                "Правило: recent_count>=3, recent_rate>=40%, historical_rate<=20%, hourly_baseline<=15%.",
                                f"Кластер {cluster.cluster_id}: recent={recent_count}/{len(recent)} ({recent_rate:.0%}).",
                                f"Историческая доля: {older_count}/{len(older)} ({older_rate:.0%}).",
                                f"Часовой baseline (hour={recent_hour}): {hourly_baseline_rate:.0%}.",
                            ],
                            related_cluster_id=cluster.cluster_id,
                        )
                    )

        metric_values: dict[str, list[float]] = defaultdict(list)
        for event in filtered_events:
            if event.metric and event.value is not None:
                metric_values[event.metric].append(event.value)

        for metric, values in metric_values.items():
            if len(values) < 6:
                continue
            median = statistics.median(values)
            deviations = [abs(v - median) for v in values]
            mad = statistics.median(deviations)
            if mad == 0:
                continue
            last = values[-1]
            robust_z = abs(last - median) / (1.4826 * mad)
            if robust_z >= 3:
                anomaly_key = ("metric_outlier", None, metric)
                if anomaly_key in seen_anomaly_keys:
                    continue
                seen_anomaly_keys.add(anomaly_key)
                anomalies.append(
                    LogAnomaly(
                        kind="metric_outlier",
                        severity=Severity.warning,
                        confidence=min(0.95, round(0.65 + robust_z / 10, 2)),
                        reason=f"Метрика {metric} имеет статистически значимое отклонение.",
                        evidence=[
                            "Правило: robust-z >= 3 на базе median/MAD.",
                            f"Текущее значение: {last:.2f}",
                            f"Медиана: {median:.2f}, MAD: {mad:.2f}, robust-z: {robust_z:.2f}",
                        ],
                        related_metric=metric,
                    )
                )

        anomalies.sort(key=lambda item: item.confidence, reverse=True)
        anomalies = anomalies[:max_anomalies]
        summary = [
            f"Проанализировано событий: {total} (окно limit={limit})",
            f"Найдено кластеров: {len(clusters)} (показано top={max_clusters})",
            f"Обнаружено аномалий: {len(anomalies)} (показано top={max_anomalies})",
        ]
        if filtered_out:
            summary.append(f"Исключено ignore-правилами: {filtered_out} из {total_before_filters}.")
        if anomalies:
            summary.append(f"Топ-причина: {anomalies[0].reason}")

        return LogAnalyticsInsight(
            asset_id=asset_id,
            analyzed_events=total,
            clusters=clusters,
            anomalies=anomalies,
            summary=summary,
        )

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

    def build_log_analytics_overview(
        self,
        limit_per_asset: int = 300,
        max_assets: int = 50,
        max_clusters: int = 30,
        max_anomalies: int = 20,
        ignore_sources: set[str] | None = None,
        ignore_signatures: set[str] | None = None,
        asset_ids: set[str] | None = None,
    ) -> LogAnalyticsOverview:
        all_assets = self.list_assets()
        if asset_ids is not None:
            all_assets = [asset for asset in all_assets if asset.id in asset_ids]
        assets = all_assets[:max_assets]
        summaries: list[LogAnalyticsAssetSummary] = []
        by_kind: Counter[str] = Counter()
        by_severity: Counter[str] = Counter()

        for asset in assets:
            insight = self.build_log_analytics(
                asset.id,
                limit=limit_per_asset,
                max_clusters=max_clusters,
                max_anomalies=max_anomalies,
                ignore_sources=ignore_sources,
                ignore_signatures=ignore_signatures,
            )
            top_severity = insight.anomalies[0].severity if insight.anomalies else None
            top_reason = insight.anomalies[0].reason if insight.anomalies else None
            summaries.append(
                LogAnalyticsAssetSummary(
                    asset_id=asset.id,
                    analyzed_events=insight.analyzed_events,
                    anomalies_total=len(insight.anomalies),
                    top_severity=top_severity,
                    top_reason=top_reason,
                )
            )
            for anomaly in insight.anomalies:
                by_kind[anomaly.kind] += 1
                by_severity[anomaly.severity.value] += 1

        summaries.sort(
            key=lambda item: (
                item.anomalies_total,
                2 if item.top_severity == Severity.critical else 1 if item.top_severity == Severity.warning else 0,
                item.analyzed_events,
            ),
            reverse=True,
        )

        assets_with_anomalies = sum(1 for item in summaries if item.anomalies_total > 0)
        total_anomalies = sum(item.anomalies_total for item in summaries)

        return LogAnalyticsOverview(
            assets_considered=len(summaries),
            assets_with_anomalies=assets_with_anomalies,
            total_anomalies=total_anomalies,
            by_kind=dict(by_kind),
            by_severity=dict(by_severity),
            assets=summaries,
        )

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
