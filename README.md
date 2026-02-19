# InfraMind Monitor

Платформа интеллектуального мониторинга ИТ‑инфраструктуры: серверов, дисковых полок, сетевого и инженерного оборудования.

## Что решает

InfraMind Monitor объединяет классический мониторинг и ИИ‑аналитику:

- собирает метрики и события с серверов, СХД, hypervisor, сетевых устройств;
- проверяет системные и сервисные логи (Linux/Windows, iDRAC/iLO/IPMI, syslog, journald, EventLog);
- выявляет деградации, ошибки конфигурации и проблемы оптимизации;
- автоматически формирует рекомендации по исправлению;
- прогнозирует инциденты и capacity‑риски (диск, память, CPU, сеть);
- помогает при root cause analysis (RCA) через корреляцию событий.

## Ключевые сценарии

1. **Проактивное обнаружение проблем**
   - рост SMART‑ошибок дисков;
   - деградация RAID/полки;
   - увеличение latency на storage‑узлах;
   - перегрев, PSU/fan события из BMC (iDRAC/iLO).

2. **Интеллектуальный анализ логов**
   - выделение аномалий в лог‑потоке;
   - группировка повторяющихся ошибок;
   - классификация по критичности и сервисному влиянию.

3. **Оптимизация инфраструктуры**
   - поиск “горячих”/“холодных” узлов;
   - рекомендации по ребалансировке, тюнингу I/O и планированию ресурсов;
   - контроль SLA/SLO и качества сервиса.

4. **Прогнозирование**
   - вероятность отказа узла/диска;
   - прогноз заполнения хранилища;
   - предупреждения об инцидентах до фактического сбоя.

## Архитектура (высокоуровневая)

```text
[Collectors/Agents] -> [Ingestion Bus] -> [TSDB + Log Store + CMDB]
                                |                 |
                                v                 v
                        [Rule Engine]      [AI/ML Engine]
                                \                 /
                                 \               /
                                  -> [Alerting + Recommendation API]
                                                |
                                                v
                                     [Web UI + ChatOps + ITSM]
```

### Компоненты

- **Collectors/Agents**:
  - SNMP, Redfish, IPMI, WMI/WinRM, SSH, Syslog, Prometheus exporters;
  - адаптеры к VMware/Hyper‑V/Kubernetes.
- **Ingestion Bus**:
  - Kafka/NATS/RabbitMQ для event streaming.
- **Хранилища**:
  - TSDB (VictoriaMetrics/Prometheus/InfluxDB),
  - Log store (OpenSearch/ClickHouse/Loki),
  - CMDB/metadata (PostgreSQL).
- **Rule Engine**:
  - классические алерты по порогам/паттернам.
- **AI/ML Engine**:
  - аномалия и тренд‑анализ,
  - NLP разбор логов,
  - ранжирование рисков и генерация рекомендаций.
- **Рекомендательный слой**:
  - runbook‑подсказки,
  - auto-ticket в ITSM,
  - отчёты для SRE/DevOps/инфраструктурных команд.

## Роли ИИ в системе

- **Log Intelligence**: извлечение сигнатур, поиск новых классов ошибок.
- **Predictive Maintenance**: оценка вероятности отказов оборудования.
- **Capacity Forecasting**: прогноз потребления ресурсов (дни/недели/месяцы).
- **Optimization Advisor**: советы по параметрам ОС/СХД/виртуализации.
- **RCA Copilot**: объяснение “почему сработал алерт”, цепочка причин.

## Пример рекомендаций

- “На узле `srv-db-03` за 6 часов вырос `%iowait` с 8% до 29%, совпадает с burst записи в LUN‑12. Рекомендуется проверить очередь контроллера и увеличить глубину очереди до N, затем повторно измерить latency.”
- “Диск `slot-7` в полке `shelf-a2` имеет растущий reallocated sector count. Вероятность отказа в 14 дней — 0.78. Рекомендуется hot‑swap в ближайшее окно.”
- “На iDRAC зафиксированы 12 thermal warning за сутки в стойке R3. Проверьте airflow/фильтры и перераспределите нагрузку между узлами R3‑01 и R3‑02.”

## MVP (12 недель)

### Этап 1 (недели 1–4)

- Базовый сбор метрик/логов с Linux + iDRAC + SNMP устройств.
- Дашборды состояния и rule‑based алерты.
- Интеграция с Telegram/Slack/email.

### Этап 2 (недели 5–8)

- AI‑анализ логов: кластеризация и детекция аномалий.
- Первые рекомендации по runbook.
- Карта зависимостей сервисов и оборудования.

### Этап 3 (недели 9–12)

- Прогнозирование capacity и вероятности отказов.
- RCA‑отчёты по инцидентам.
- Интеграция с ITSM (Jira/ServiceNow).

## Нефункциональные требования

- Multi-tenant и RBAC.
- Аудит действий и explainability для ИИ‑решений.
- Безопасное хранение секретов и credentials rotation.
- Горизонтальное масштабирование ingestion и аналитики.
- Работа в on-prem и hybrid cloud.

## KPI проекта

- снижение MTTR на 25–40%;
- снижение количества критических инцидентов на 20%+;
- точность прогноза capacity > 85% на горизонте 30 дней;
- уменьшение ложноположительных алертов на 30%.

## Риски и как снижать

- **Шумные данные и плохое качество логов** → data quality pipeline + нормализация.
- **Ложные рекомендации ИИ** → human-in-the-loop, explainability, безопасные пороги автодействий.
- **Сложная интеграция с legacy** → адаптерный слой и поэтапное подключение.
- **Безопасность** → минимальные привилегии агентов, mTLS, сегментация сети.

## Стек (пример)

- Backend: Go или Python (FastAPI).
- Data pipeline: Kafka + Flink/Spark (опционально).
- Storage: VictoriaMetrics + OpenSearch + PostgreSQL.
- AI: Python (scikit-learn, PyTorch), LLM для лог‑резюме и рекомендаций.
- UI: React + Grafana embeds.
- Deploy: Kubernetes + Helm + ArgoCD.

---

Если хотите, следующим шагом можно расписать **детальную схему модулей и API-контракты** (что, куда и в каком формате отправляет каждый агент), а также сделать **backlog задач для MVP по спринтам**.

## Текущий статус реализации

В репозитории реализован стартовый backend-прототип (FastAPI), который уже можно запускать локально:

- регистрация инфраструктурных объектов (assets);
- приём событий/логов (events);
- выдача базовой ИИ-подобной рекомендации и risk score по объекту;
- health-check endpoint.

### Быстрый старт

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8050 --reload
```

После запуска API доступно на `http://127.0.0.1:8050`.

### Основные endpoint'ы MVP

- `GET /health`
- `POST /assets`
- `POST /events`
- `GET /assets/{asset_id}/events`
- `GET /assets/{asset_id}/recommendation`

## Интерфейс и автосбор данных

Да, интерфейс уже есть в двух вариантах:

1. **Swagger UI**: `http://127.0.0.1:8050/docs` — удобно вручную отправлять события/метрики.
2. **ReDoc**: `http://127.0.0.1:8050/redoc` — документация API.

Также добавлена стартовая web-страница `GET /` с быстрыми ссылками на интерфейсы.

### Как добавлять логи и метрики автоматически

Для агентов добавлен batch endpoint:

- `POST /ingest/events`

Формат payload:

```json
{
  "events": [
    {
      "asset_id": "srv-01",
      "source": "agent",
      "message": "root fs usage",
      "metric": "disk_used_pct",
      "value": 72.5,
      "severity": "info",
      "timestamp": "2026-02-19T14:00:00Z"
    }
  ]
}
```

### Готовый пример агента

В репозитории добавлен `scripts/agent.py`, который:

- регистрирует asset (если ещё не добавлен);
- периодически читает системные метрики (`/proc/loadavg`, usage диска `/`);
- читает последние строки системного лога (`/var/log/syslog` или другой файл);
- отправляет всё в `POST /ingest/events`.

Запуск:

```bash
python scripts/agent.py --api http://127.0.0.1:8050 --asset-id srv-01 --interval 30
```

Для production это можно запускать как `systemd` service/timer или DaemonSet в Kubernetes.

## Что сделали дальше по плану

Следующий шаг MVP реализован:

- добавлено **персистентное хранение** в SQLite (`app/storage.py`) вместо только in-memory состояния;
- добавлен `GET /assets` для просмотра подключённых объектов;
- добавлен `GET /assets/{asset_id}/alerts` для rule-based алертов (iowait/thermal/SMART);
- добавлен `GET /overview` для сводки (кол-во assets, событий и критичных узлов).

Это приближает платформу к операционному режиму: данные сохраняются между перезапусками API и уже есть базовый “операционный” обзор состояния.

## Следующий шаг: Windows Event Log + dashboard

Идём по плану дальше и закрываем два направления сразу:

1. **Сбор логов из Windows**
2. **Базовый дашборд для оператора**

### 1) Windows Event Log collection

Добавлен скрипт: `scripts/windows_eventlog_agent.ps1`.

Что делает:

- регистрирует Windows-host как asset в API;
- читает события из `Application` и `System` за последние N минут;
- нормализует уровень критичности (`info/warning/critical`);
- отправляет пачку событий в `POST /ingest/events`.

Запуск на Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_eventlog_agent.ps1 -Api "http://<api-host>:8050" -AssetId "win-01" -IntervalSec 30 -LookbackMinutes 5
```

### 2) Dashboard

Добавлен endpoint `GET /dashboard` — простой HTML-дашборд:

- общая сводка (assets/events/critical assets),
- таблица по узлам (тип, локация, кол-во событий, кол-во алертов).

Это быстрый operational view до полноценного UI (React/Grafana).

## Запуск на порту 8050

По умолчанию проект теперь ориентирован на порт **8050**.

Локальный запуск:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8050 --reload
```

API и интерфейсы:

- `http://127.0.0.1:8050/`
- `http://127.0.0.1:8050/docs`
- `http://127.0.0.1:8050/dashboard`

## Развёртывание через Portainer

Добавлены файлы:

- `Dockerfile`
- `docker-compose.portainer.yml`
- `.env.example`

### Вариант A: Portainer Stack из Git

1. В Portainer откройте **Stacks** → **Add stack**.
2. Выберите **Repository** и укажите URL репозитория.
3. В поле compose file path укажите: `docker-compose.portainer.yml`.
4. Deploy stack.

### Вариант B: Загрузить compose вручную

Скопируйте содержимое `docker-compose.portainer.yml` в окно Stack editor и нажмите Deploy.

После деплоя сервис будет доступен на `http://<host>:8050`.
