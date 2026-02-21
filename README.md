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

## Следующий шаг: корреляции по Windows событиям

Продолжаем по плану: добавлен базовый слой корреляции инцидентов для Windows Event Log.

### Что добавлено

- новый API endpoint: `GET /assets/{asset_id}/insights`;
- dashboard теперь показывает колонку `Insights` по каждому asset;
- в рекомендациях учитываются найденные корреляции (добавляются действия вида `Correlation: ...`).

### Какие паттерны уже ловим

- `EventID=6008` / `EventID=41` → repeated unexpected shutdown pattern;
- `EventID=4625` (много раз) → burst of failed logons;
- `EventID=7/51/55/153` → кластер storage ошибок в Windows.

Это переход к следующему уровню после “сырых алертов”: теперь система не только хранит и показывает события,
но и формирует контекстно-связанные гипотезы причин.

## UI для управления ассетами и событиями (без ручного API)

Добавлен встроенный web-интерфейс для базовых операций:

- `GET /ui/assets` — форма создания/обновления asset + таблица зарегистрированных узлов;
- `GET /ui/events` — форма добавления событий для выбранного asset;
- `GET /dashboard` — теперь содержит быстрые ссылки на эти формы.

То есть можно работать через браузер, не отправляя JSON вручную в Swagger/Postman.

## Как работает Windows-скрипт (коротко)

Да, логика именно такая: вы запускаете `scripts/windows_eventlog_agent.ps1` на Windows-сервере,
и он **сам отправляет** события на ваш InfraMind API.

Что нужно перед запуском:

1. API InfraMind должен быть доступен по сети (например `http://<ip-сервера>:8050`).
2. На Windows должна быть разрешена execution policy для скрипта (или запуск с `-ExecutionPolicy Bypass`).
3. Указать корректный `-Api` и `-AssetId`.

Пример:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_eventlog_agent.ps1 -Api "http://10.10.10.20:8050" -AssetId "win-dc-01" -IntervalSec 30 -LookbackMinutes 5
```

После старта скрипт:

- регистрирует asset в `/assets`;
- циклически читает Windows EventLog (`Application` + `System`);
- конвертирует события в общий формат;
- отправляет батч в `/ingest/events` каждые `IntervalSec` секунд.

### Частая ошибка после redeploy в Portainer

Если в логах видите ошибку:

`RuntimeError: Form data requires "python-multipart" to be installed`

это означает, что контейнер был собран без зависимости для `Form(...)` endpoint'ов FastAPI.

В проект уже добавлена зависимость `python-multipart` в `requirements.txt`.

Что сделать:

1. В Portainer откройте Stack.
2. Нажмите **Pull and redeploy** (или **Recreate**) с пересборкой образа.
3. Убедитесь, что новый контейнер поднялся без этой ошибки.

### Проблема с "?????" в Windows-сообщениях

Если в dashboard вместо русского текста идут `?????`, обычно это из-за отправки тела запроса не в UTF-8.

В `scripts/windows_eventlog_agent.ps1` уже добавлена отправка JSON как UTF-8 bytes
(`application/json; charset=utf-8`), чтобы Unicode-текст из EventLog сохранялся корректно.

После обновления скрипта:

1. замените скрипт на хосте Windows на свежую версию;
2. перезапустите его;
3. новые события будут приходить с нормальной кириллицей.

Старые уже сохранённые "битые" записи в БД останутся как есть (это ожидаемо).

## Следующий шаг к сбору без скриптов (agentless)

Добавлена основа для сценария "указал IP/учётку и сбор пошёл":

- `GET /ui/collectors` — UI для настройки collector targets;
- `POST /ui/collectors` — сохранение target (тип, адрес, порт, учётка, интервал, привязка к asset);
- API: `GET /collectors`, `POST /collectors`, `DELETE /collectors/{target_id}`.

Поддерживаемые типы target:

- `winrm` (Windows),
- `ssh` (Linux/Unix),
- `snmp` (сетевое/СХД).

Сейчас это конфигурационный слой (foundation). Следующий шаг — worker/scheduler,
который будет автоматически обходить enabled targets по `poll_interval_sec` и собирать данные без отдельных скриптов на хостах.


## Worker для agentless-сбора (первый рабочий шаг)

Сделан базовый scheduler/worker внутри API:

- берёт `enabled` targets из `collector_targets`;
- учитывает `poll_interval_sec`;
- выполняет TCP probe до `address:port`;
- создаёт событие `source=agentless_<type>` в asset (успех/ошибка доступности).

Управление:

- `GET /worker/status` — включён ли worker;
- `POST /worker/run-once` — принудительный один цикл (удобно для проверки).

Переменная окружения:

- `ENABLE_AGENTLESS_WORKER=1` (по умолчанию включён).

Важно: это первый этап agentless-режима. На следующем шаге добавим
реальные протокольные сборщики (WinRM/SSH/SNMP запросы), а не только reachability probe.


### Worker status/targets

Для контроля worker добавлены endpoint'ы:

- `GET /worker/status` — running/cycle_count/tick/timeout;
- `GET /worker/targets` — последний статус по каждой цели (ok, latency, failure_streak, last_run_ts);
- `POST /worker/run-once` — форсированный цикл.

Доп. переменные окружения:

- `WORKER_TICK_SEC` (по умолчанию `2`),
- `WORKER_TIMEOUT_SEC` (по умолчанию `2`).

## Следующий шаг (реализовано): checkpoint + dedup для worker

Чтобы перейти от демо-режима к стабильному agentless-сбору, добавлено:

- `collector_state` в БД (last_run/success/error/cursor/failure_streak);
- сохранение состояния после каждого цикла worker;
- дедупликация событий по fingerprint (одинаковые события не дублируются в хранилище);
- `/worker/targets` теперь показывает данные из persisted state.

Это база для следующего шага: подключение реальных WinRM/SSH/SNMP collectors с cursor-based чтением.

## Следующий шаг (реализовано): protocol-aware worker path

Продолжаем по порядку. В worker добавлен протокольный dispatch:

- `winrm` path,
- `ssh` path,
- `snmp` path.

Пока сбор внутри каждого path остаётся на уровне reachability probe, но уже есть:

- progression `last_cursor` (persisted),
- persisted state (`last_run`, `last_success`, `last_error`, `failure_streak`),
- dedup с окном по времени (дубли отбрасываются только в пределах dedup window, а не навсегда).

Это подготовка к следующему шагу: подставить реальный WinRM pull EventLog вместо probe без изменения общей архитектуры worker.

## Следующий шаг (реализовано): реальный WinRM pull

В `winrm` path worker теперь делает не только TCP-probe, а пытается выполнить реальный pull EventLog через WinRM:

- подключение к `http://<address>:<port>/wsman`;
- выполнение PowerShell `Get-WinEvent` (System/Application) c фильтром по `RecordId > last_cursor`;
- парсинг результата и запись событий в хранилище;
- обновление `last_cursor` в `collector_state`.

Зависимость для этого пути: `pywinrm` (добавлена в `requirements.txt`).

Если WinRM недоступен/не настроен, worker пишет диагностическое событие об ошибке pull и увеличивает `failure_streak`.

## Следующий шаг (реализовано): настраиваемый WinRM pull profile

Добавили параметры WinRM-коллектора, чтобы реальный pull можно было тонко настроить под вашу среду:

- `winrm_transport` (`ntlm`/`basic`/`kerberos`);
- `winrm_use_https` (использовать `https://.../wsman`);
- `winrm_validate_tls` (проверка TLS-сертификата сервера);
- `winrm_event_logs` (каналы через запятую, например `System,Application,Security`);
- `winrm_batch_size` (сколько событий за один pull).

Где это доступно:

- UI: `/ui/collectors` (новые поля в форме);
- API: `POST /collectors` (те же поля в JSON);
- worker использует эти параметры напрямую в `pywinrm.Session` и PowerShell `Get-WinEvent` запросе.

Пример JSON для `POST /collectors`:

```json
{
  "id": "win-host-01",
  "name": "Windows DC collector",
  "address": "10.10.20.15",
  "collector_type": "winrm",
  "port": 5986,
  "username": "DOMAIN\\svc-monitor",
  "password": "***",
  "poll_interval_sec": 60,
  "enabled": true,
  "asset_id": "srv-dc-01",
  "winrm_transport": "kerberos",
  "winrm_use_https": true,
  "winrm_validate_tls": true,
  "winrm_event_logs": "System,Security",
  "winrm_batch_size": 100
}
```

## Следующий шаг (реализовано): защита credential'ов collector targets

Сделан шаг по безопасности хранения учётных данных collector targets:

- пароль collector target теперь шифруется при сохранении в SQLite (если задан `APP_SECRET_KEY`);
- при чтении для worker выполняется расшифровка (для обратной совместимости старые plaintext-значения тоже читаются);
- `GET /collectors` возвращает маскированный пароль (`********`), чтобы не светить секреты в UI/API-ответах.

Настройка:

- задайте `APP_SECRET_KEY` (Fernet key) в окружении/Portainer;
- без ключа будет режим passthrough для совместимости (рекомендуется выставить ключ в production).

### Что дальше по плану

Следующий шаг: **реальный SSH pull** (не только TCP-probe), с выполнением команд для сбора логов/метрик и с checkpoint-логикой, аналогичной WinRM path.

## Следующий шаг (реализовано): реальный SSH pull

Сделан следующий шаг по roadmap: для `ssh` collector target worker больше не ограничивается TCP-probe,
а выполняет реальный pull данных по SSH:

- подключение к удалённому хосту по `username/password`;
- выполнение команды метрик (`ssh_metrics_command`, по умолчанию `cat /proc/loadavg`);
- чтение хвоста системного лога (`tail -n N <ssh_log_path>`);
- сохранение результатов в события `ssh_metrics` и `ssh_log`;
- обновление checkpoint (`last_cursor`) и `collector_state`.

Добавлены параметры SSH profile в target:

- `ssh_metrics_command`;
- `ssh_log_path`;
- `ssh_tail_lines`.

### Что дальше по плану

Следующий шаг: **реальный SNMP pull** (OID polling + нормализация в метрики/события), чтобы закрыть третий protocol path.

## Следующий шаг (реализовано): реальный SNMP pull

Сделан следующий шаг roadmap: `snmp` path теперь выполняет реальный poll OID'ов, а не только TCP-probe.

Что реализовано:

- configurable SNMP profile в collector target:
  - `snmp_community`
  - `snmp_version` (`2c`/`3`)
  - `snmp_oids` (список OID через запятую)
- worker path `_collect_snmp_target`:
  - читает OID'ы через `pysnmp` (`getCmd`),
  - нормализует результат в `snmp_metric` события,
  - обновляет `last_cursor` и `collector_state`,
  - при ошибках формирует `agentless_snmp` события с `failure_streak`.

Безопасность:

- `snmp_community` хранится в БД в шифрованном виде (при включенном `APP_SECRET_KEY`) и маскируется в `GET /collectors`.

### Что дальше по плану

Следующий шаг: **миграция lifecycle на FastAPI lifespan** (вместо deprecated `@app.on_event`) и добавление health-диагностики по воркеру/коллекторам в отдельном статус-виджете.

## Следующий шаг (реализовано): FastAPI lifespan + worker health diagnostics

Сделали следующий шаг по плану для стабилизации runtime и наблюдаемости:

- lifecycle приложения переведён на `lifespan` (вместо deprecated `@app.on_event`);
- добавлен endpoint `GET /worker/health` с агрегированным состоянием worker (`running`, `tracked`, `failed`, `stale`, `cycle_count`);
- в `/dashboard` добавлен status-widget по worker health с быстрым переходом на JSON-диагностику.

### Что дальше по плану

Следующий шаг: добавить lightweight history/тренды по worker health (например, последние N циклов с ошибками по target) и вывести это в отдельной UI-странице диагностики collector'ов.

## Следующий шаг (реализовано): history/trends по worker + diagnostics UI

Сделали следующий шаг по плану наблюдаемости worker:

- добавлен endpoint `GET /worker/history?limit=N` с последними циклами poll по target;
- добавлена UI-страница `GET /ui/diagnostics` с таблицей последних запусков (target/type/accepted/failure/cursor/error);
- на главную и в dashboard добавлены ссылки на diagnostics.

История хранится как lightweight ring-buffer в памяти процесса (до 500 записей), что закрывает быстрый operational use-case без миграции схемы БД.

### Что дальше по плану

Следующий шаг: сделать persisted history/telemetry (в SQLite) и добавить фильтры/графики по target на diagnostics-странице.

## Следующий шаг (реализовано): persisted history/telemetry + filters в diagnostics

Сделали следующий шаг из плана:

- история worker теперь сохраняется в SQLite (`worker_history`), а не только в памяти;
- добавлена миграционная совместимость для старых БД без `events.fingerprint` (авто-добавление колонки при старте);
- `GET /worker/history` поддерживает фильтры: `target_id`, `collector_type`, `has_error`;
- `GET /ui/diagnostics` получил фильтры по target/type/error и работает поверх persisted history.

Это значит, что история не теряется после рестарта контейнера и её можно использовать как базовый telemetry trail для расследования проблем по collector target.

### Что дальше по плану

Следующий шаг: добавить графики/агрегации по истории (ошибки/успехи/accepted events по времени) и экспорт диагностики (CSV/JSON dump) из UI.

## Следующий шаг (реализовано): графики/агрегации + CSV export в diagnostics

Выполнен следующий шаг:

- в `GET /ui/diagnostics` добавлены агрегаты (`runs/ok/errors/accepted_events_sum`);
- добавлены lightweight-графики:
  - bar по ошибкам/успехам в разрезе collector type,
  - trend line по `accepted_events`;
- добавлен экспорт `GET /worker/history.csv` с фильтрами `target_id`, `collector_type`, `has_error`;
- на UI добавлена ссылка на скачивание отфильтрованного CSV.

### Что дальше по плану

Следующий шаг: вынести diagnostics view на отдельные data endpoints для фронтенда (JSON агрегации/таймсерии) и добавить автообновление виджета без перезагрузки страницы.

## Следующий шаг (реализовано): data endpoints + автообновление diagnostics

Сделали следующий шаг roadmap:

- добавлены отдельные data endpoint'ы для фронтенд-виджета diagnostics:
  - `GET /worker/diagnostics/summary`
  - `GET /worker/diagnostics/trend`
- `GET /ui/diagnostics` теперь использует JS автообновление (poll каждые 10 секунд) без перезагрузки страницы;
- summary/charts на странице обновляются из этих endpoint'ов, а таблица и CSV-фильтры остаются совместимыми с текущим workflow.

### Что дальше по плану

Следующий шаг: перейти от polling к server-push (SSE/WebSocket) для near-real-time обновления diagnostics и вынести визуализацию в более структурированный фронтенд-компонент.

## Следующий шаг (реализовано): server-push diagnostics через SSE

Сделали следующий шаг roadmap:

- добавлен endpoint `GET /worker/diagnostics/stream` (SSE), который пушит `summary + trend` по тем же фильтрам (`target_id`, `collector_type`, `has_error`);
- `GET /ui/diagnostics` теперь подписывается на SSE для near-real-time обновления карточки summary и графиков;
- добавлен fallback на polling (`/worker/diagnostics/summary` и `/worker/diagnostics/trend`) если `EventSource` недоступен или SSE-соединение оборвалось.

### Что дальше по плану

Следующий шаг: выделить diagnostics UI в более структурированный фронтенд-компонент (с отдельным JS-модулем и переиспользуемыми функциями рендера), чтобы упростить развитие визуализации и дальнейшие real-time виджеты.

## Следующий шаг (реализовано): визуальный dashboard refresh (операторский UI)

Сделали следующий шаг roadmap по UI:

- переработан `GET /dashboard` в более «операторский» вид (карточки KPI, logs trend, top assets, recent alerts);
- добавлены агрегаты по источникам (`windows_eventlog`, `syslog`, `agentless_*`) и распределение по severity;
- сохранены быстрые переходы в workflow (`/ui/assets`, `/ui/events`, `/ui/collectors`, `/ui/diagnostics`) и виджет состояния worker.

### Что дальше по плану

Следующий шаг: вынести dashboard/diagnostics фронтенд-логику в отдельный JS-модуль + API-first контракты для графиков (подготовка к более богатым интерактивным компонентам и RBAC/UI-ролям).

## Следующий шаг (реализовано): модульный dashboard frontend + API-first data contract

Сделали следующий шаг roadmap:

- добавлен API endpoint `GET /dashboard/data` с агрегированным payload для визуализации (KPI, источники, trend, severity, top assets, recent alerts, assets table);
- фронтенд dashboard вынесен в отдельный модуль `app/static/dashboard.js`;
- `GET /dashboard` теперь рендерит shell-страницу и подключает модуль, который рисует виджеты из initial payload и обновляет данные через `/dashboard/data` по таймеру.

### Что дальше по плану

Следующий шаг: унифицировать dashboard + diagnostics на общем фронтенд-слое (единый JS toolkit/components), добавить фильтры периода/asset/type и подготовить базу под RBAC-видимость виджетов.

## Следующий шаг (реализовано): dashboard filters (period/asset/source)

Сделали следующий шаг roadmap:

- для `GET /dashboard/data` добавлены фильтры `period_days`, `asset_id`, `source`;
- в dashboard добавлена панель фильтров (период, asset, source), которая перерисовывает виджеты на лету;
- KPI/графики/таблицы теперь отражают отфильтрованный срез (`events_filtered`).

### Что дальше по плану

Следующий шаг: применить ту же filter-модель к diagnostics и добавить role-based UI visibility (RBAC), чтобы разные роли видели только разрешённые блоки/targets.

## Следующий шаг (реализовано): role-based UI visibility foundation (RBAC)

Сделали следующий шаг roadmap:

- в `GET /dashboard/data` добавлен параметр `role` (`viewer` / `operator` / `admin`);
- payload теперь возвращает `permissions`, по которым фронтенд скрывает/показывает чувствительные блоки (`worker health`, `recent alerts`, ссылки на collectors/diagnostics);
- на dashboard добавлен фильтр роли (`Role`) для проверки/демонстрации видимости в UI без перезагрузки архитектуры.

### Что дальше по плану

Следующий шаг: перенести ту же RBAC + filter-модель на diagnostics (включая data endpoints) и добавить server-side ограничения на чувствительные endpoint'ы, а не только UI-visibility.

## Следующий шаг (реализовано): RBAC + server-side ограничения для worker endpoints

Сделали следующий шаг roadmap:

- role/filer-модель перенесена на diagnostics (`role` добавлен в summary/trend/stream/UI);
- добавлены server-side ограничения для чувствительных worker endpoint'ов:
  - `GET /worker/history`
  - `GET /worker/history.csv`
  - `GET /worker/targets`
  - `POST /worker/run-once`
  (`viewer` получает `403`);
- `ui/diagnostics` показывает текущую роль и в режиме `viewer` работает как ограниченный diagnostics-view без raw history.

### Что дальше по плану

Следующий шаг: ввести реальную аутентификацию (не query-параметр role), выдачу роли из auth-контекста и применить те же server-side policy-check'и к остальным чувствительным API (collectors/events ingestion/admin actions).

## Следующий шаг (реализовано): auth-context роль + RBAC policy checks

Сделали более крупный шаг:

- добавлен endpoint `GET /auth/whoami` для проверки разрешённой роли из auth-контекста;
- роль теперь может приходить из заголовков (`X-Auth-Token`/`X-Role`) и применяется в dashboard/diagnostics/worker policy-checks;
- сохранён мягкий fallback на query role (для обратной совместимости), но основная модель — auth-context роль;
- server-side ограничения для чувствительных worker endpoint'ов работают как через query role, так и через role из заголовков.

### Что дальше по плану

Следующий шаг: убрать query-role fallback из production режима, подключить полноценную аутентификацию (JWT/session), централизовать policy middleware и закрыть этой моделью collectors/events ingestion/admin actions.

## Следующий шаг (реализовано): централизованный policy-check для admin/operator API

Сделали ещё один крупный модульный шаг:

- добавлен единый helper `_require_role(...)` с иерархией ролей (`viewer` < `operator` < `admin`);
- server-side RBAC теперь централизованно применяется не только к worker, но и к API управления/ingest:
  - `GET/POST/DELETE /collectors`
  - `POST /events`
  - `POST /ingest/events`
  - `POST /assets`
- добавлены тесты, подтверждающие, что `viewer` получает `403`, а `operator` может выполнять эти операции через auth-context (`X-Role`).

### Что дальше по плану

Следующий шаг: вынести role/policy в отдельный middleware/dependency слой (не в каждом endpoint вручную), добавить JWT/session auth provider и переключить production на `ALLOW_QUERY_ROLE=0` по умолчанию.

## Следующий шаг (реализовано): auth-provider module + audit + secure-by-default fallback policy

Сделали сразу укрупнённый модуль вместо мелких шагов:

- добавлен auth-provider слой:
  - `POST /auth/login` (session cookie),
  - `POST /auth/logout`,
  - `GET /auth/whoami`;
- добавлен `GET /auth/audit` (admin-only) для просмотра deny/allow записей policy-check;
- `ALLOW_QUERY_ROLE` переведён в secure-default (`0`) для production-профиля;
- добавлены env-параметры для auth/session (`AUTH_USERS`, `AUTH_TOKENS`, `SESSION_SECRET`, `SESSION_TTL_SEC`, `SESSION_COOKIE_NAME`);
- сохранена совместимость: query-role можно временно включить через `ALLOW_QUERY_ROLE=1`.

### Что дальше по плану (крупными блоками)

1. **Identity Module** — перейти с встроенного users-map на JWT/OIDC provider.
2. **Policy Module** — вынести `_require_role` в dependency/middleware слой и покрыть все endpoint-группы единообразно.
3. **Operations Module** — audit persistence (SQLite), ротация/экспорт, алерты по deny-spikes.
4. **Product Module** — multi-tenant visibility + role-based UX presets для dashboard/diagnostics.
