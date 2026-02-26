# InfraMind Monitor — практическая инструкция (RU)

Этот документ описывает **текущий рабочий функционал MVP**, как с ним работать через UI/API и как подключать источники (в т.ч. Windows EventLog и iDRAC).

## 1) Что уже реализовано

### 1.1 Базовые сущности
- **Asset** — объект инфраструктуры (сервер, BMC, сеть, полка хранения).
- **Event** — событие/лог/метрика, привязанная к asset.
- **CollectorTarget** — цель agentless-сбора (WinRM/SSH/SNMP).
- **CollectorState** — техническое состояние collector'а (курсор, ошибки, streak).
- **AI policies** — политики фильтрации источников/сигнатур в AI log analytics.

### 1.2 API и UI
- REST API для assets/events/collectors/worker/AI analytics.
- UI страницы:
  - `/ui/assets` — создание и просмотр asset'ов,
  - `/ui/events` — ручное добавление событий,
  - `/ui/collectors` — настройка collector targets,
  - `/ui/diagnostics` — диагностика worker,
  - `/ui/ai` и `/ui/ai/policies` — AI аналитика и политики.
- Технические интерфейсы: `/docs`, `/redoc`, `/dashboard`.

### 1.3 Авто-сбор
Поддержаны три collector-типа:
- **winrm** — pull Windows EventLog (`Get-WinEvent`) с курсором `RecordId`.
- **ssh** — выполнение команд для метрик + `tail` лог-файла.
- **snmp** — polling OID и нормализация в события.

### 1.4 Аналитика и рекомендации
- `/assets/{asset_id}/recommendation` — risk_score + summary + actions.
- `/assets/{asset_id}/alerts` — базовые rule-based алерты.
- `/assets/{asset_id}/ai-log-analytics` — кластеры + аномалии + summary.
- `/ai-log-analytics/overview` — обзор аномалий по нескольким asset.

---

## 2) Быстрый запуск и базовый workflow

## 2.1 Запуск
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8050 --reload
```

## 2.2 Минимальный сценарий (вручную)
1. Создайте asset (`POST /assets`).
2. Отправьте событие (`POST /events`) или пачку (`POST /ingest/events`).
3. Проверьте:
   - `/assets/{asset_id}/events`
   - `/assets/{asset_id}/recommendation`
   - `/assets/{asset_id}/ai-log-analytics`

---

## 3) Поля: что за что отвечает

## 3.1 Asset
| Поле | Тип | Назначение |
|---|---|---|
| `id` | string | Уникальный идентификатор asset (ключ в API/БД). |
| `name` | string | Человекочитаемое имя. |
| `asset_type` | enum | Тип: `server`, `storage_shelf`, `network`, `bmc`. |
| `location` | string/null | Локация (площадка, стойка, зона). |

## 3.2 Event
| Поле | Тип | Назначение |
|---|---|---|
| `asset_id` | string | К какому asset относится событие. |
| `source` | string | Источник (`windows_eventlog`, `ssh_log`, `snmp_metric`, `idrac`, и т.д.). |
| `message` | string | Текст события/лога (основа для кластеризации и анализа). |
| `metric` | string/null | Имя метрики (если это метрика). |
| `value` | float/null | Значение метрики. |
| `severity` | enum | `info`, `warning`, `critical`. |
| `timestamp` | datetime | Время события (UTC ISO). |

> Рекомендация: для iDRAC/Windows придерживайтесь стабильного `source`, чтобы фильтры/политики работали предсказуемо.

## 3.3 CollectorTarget
Общие поля:

| Поле | Тип | Назначение |
|---|---|---|
| `id` | string | ID collector target. |
| `name` | string | Имя цели (например `win-srv-01` / `idrac-r730-01`). |
| `address` | string | IP/FQDN удалённой цели. |
| `collector_type` | enum | `winrm` / `ssh` / `snmp`. |
| `port` | int | Порт протокола (5985/5986, 22, 161). |
| `username` | string | Логин для доступа. |
| `password` | string | Пароль/секрет. |
| `poll_interval_sec` | int | Интервал опроса (>=10). |
| `enabled` | bool | Включён ли target в worker-цикле. |
| `asset_id` | string | Asset, куда будут записываться события. |

Поля для **WinRM**:

| Поле | Тип | Назначение |
|---|---|---|
| `winrm_transport` | string | Транспорт (`ntlm`, `basic`, и т.п. в рамках pywinrm). |
| `winrm_use_https` | bool | Использовать HTTPS endpoint WinRM. |
| `winrm_validate_tls` | bool | Проверять TLS-сертификат (`true`) или игнорировать (`false`). |
| `winrm_event_logs` | string | Список каналов через запятую (`System,Application,...`). |
| `winrm_batch_size` | int | Сколько записей читать за один опрос (1..500). |

Поля для **SSH**:

| Поле | Тип | Назначение |
|---|---|---|
| `ssh_metrics_command` | string | Команда метрик (по умолчанию `cat /proc/loadavg`). |
| `ssh_log_path` | string | Путь к лог-файлу на хосте. |
| `ssh_tail_lines` | int | Сколько строк читать через `tail` (1..500). |

Поля для **SNMP**:

| Поле | Тип | Назначение |
|---|---|---|
| `snmp_community` | string | SNMP community. |
| `snmp_version` | string | Версия (`2c`/`3`, в текущем коде mpModel выбирается по значению). |
| `snmp_oids` | string | OID'ы через запятую для polling. |

## 3.4 CollectorState
| Поле | Назначение |
|---|---|
| `last_success_ts` | Последний успешный запуск target. |
| `last_run_ts` | Последний запуск (в т.ч. с ошибкой). |
| `last_error` | Текст последней ошибки (если была). |
| `last_cursor` | Курсор чтения (например RecordId для WinRM). |
| `failure_streak` | Подряд неуспешных запусков. |

---

## 4) Как добавить Windows-логи

Есть два рабочих пути.

## 4.1 Путь A: agentless WinRM collector (рекомендуется)
1. Создайте asset:
```bash
curl -sS -X POST http://127.0.0.1:8050/assets \
  -H 'Content-Type: application/json' \
  -d '{"id":"win-srv-01","name":"Windows SRV 01","asset_type":"server","location":"dc1"}'
```
2. Создайте collector target типа `winrm`:
```bash
curl -sS -X POST http://127.0.0.1:8050/collectors \
  -H 'Content-Type: application/json' \
  -d '{
    "id":"winrm-win-srv-01",
    "name":"winrm-win-srv-01",
    "address":"10.10.10.21",
    "collector_type":"winrm",
    "port":5985,
    "username":"Administrator",
    "password":"Secret!",
    "poll_interval_sec":30,
    "enabled":true,
    "asset_id":"win-srv-01",
    "winrm_transport":"ntlm",
    "winrm_use_https":false,
    "winrm_validate_tls":false,
    "winrm_event_logs":"System,Application",
    "winrm_batch_size":100,
    "ssh_metrics_command":"cat /proc/loadavg",
    "ssh_log_path":"/var/log/syslog",
    "ssh_tail_lines":50,
    "snmp_community":"public",
    "snmp_version":"2c",
    "snmp_oids":"1.3.6.1.2.1.1.3.0"
  }'
```
3. Проверьте worker:
```bash
curl -sS http://127.0.0.1:8050/worker/status
curl -sS -X POST http://127.0.0.1:8050/worker/run-once
curl -sS http://127.0.0.1:8050/assets/win-srv-01/events
```

## 4.2 Путь B: локальный PowerShell-агент
Скрипт `scripts/windows_eventlog_agent.ps1`:
- регистрирует asset;
- читает Application/System за lookback;
- отправляет batch в `/ingest/events`.

Пример запуска:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_eventlog_agent.ps1 `
  -Api "http://monitor-host:8050" `
  -AssetId "win-srv-01" `
  -Location "dc1" `
  -IntervalSec 30 `
  -LookbackMinutes 5
```

---

## 5) Как добавить iDRAC

В текущем MVP нет отдельного Redfish collector-а, но iDRAC можно подключать уже сейчас двумя способами.

## 5.1 Вариант A: как `bmc` asset + SNMP collector
1. Создайте asset типа `bmc`:
```bash
curl -sS -X POST http://127.0.0.1:8050/assets \
  -H 'Content-Type: application/json' \
  -d '{"id":"idrac-r730-01","name":"iDRAC R730 #01","asset_type":"bmc","location":"rack-r3"}'
```
2. Создайте SNMP collector target с нужными OID:
```bash
curl -sS -X POST http://127.0.0.1:8050/collectors \
  -H 'Content-Type: application/json' \
  -d '{
    "id":"snmp-idrac-r730-01",
    "name":"snmp-idrac-r730-01",
    "address":"10.10.20.31",
    "collector_type":"snmp",
    "port":161,
    "username":"unused",
    "password":"unused",
    "poll_interval_sec":60,
    "enabled":true,
    "asset_id":"idrac-r730-01",
    "winrm_transport":"ntlm",
    "winrm_use_https":false,
    "winrm_validate_tls":false,
    "winrm_event_logs":"System,Application",
    "winrm_batch_size":50,
    "ssh_metrics_command":"cat /proc/loadavg",
    "ssh_log_path":"/var/log/syslog",
    "ssh_tail_lines":50,
    "snmp_community":"public",
    "snmp_version":"2c",
    "snmp_oids":"1.3.6.1.4.1.674.10892.5.4.600.12.1.5.1,1.3.6.1.2.1.1.3.0"
  }'
```
3. Выполните `run-once` и проверьте события.

## 5.2 Вариант B: пушить iDRAC события через `/ingest/events`
Если у вас уже есть внешний скрипт/интеграция (например Redfish poller), отправляйте нормализованные события напрямую:
```json
{
  "events": [
    {
      "asset_id": "idrac-r730-01",
      "source": "idrac",
      "message": "Thermal warning: inlet temperature above threshold",
      "metric": "inlet_temp_c",
      "value": 38.5,
      "severity": "warning",
      "timestamp": "2026-02-19T14:00:00Z"
    }
  ]
}
```

---

## 6) AI log analytics и политики фильтрации

### Что делает аналитика
- строит сигнатуры сообщений,
- группирует в кластеры,
- выделяет аномалии (по частоте/критичности/динамике),
- формирует объяснимую сводку.

### Как исключить шум
Используйте policy endpoint'ы:
- `POST /ai-log-analytics/policies`
- `GET /ai-log-analytics/policies`
- `DELETE /ai-log-analytics/policies/{policy_id}`

Ключевые поля policy:
- `ignore_sources` — полностью исключить source (например `agentless_ssh`).
- `ignore_signatures` — исключить конкретные сигнатуры сообщений.
- `enabled` — включить/отключить политику.
- `tenant_id` — изоляция правил по tenant.

Проверить эффект до применения можно через:
- `GET /assets/{asset_id}/ai-log-analytics/policy-dry-run`

---

## 7) Практические рекомендации по эксплуатации

- Для Windows через WinRM начните с `System,Application`, затем добавляйте каналы точечно.
- Для iDRAC сначала заведите отдельный `bmc` asset, чтобы не смешивать BMC события с ОС-сервером.
- Установите разные `poll_interval_sec`:
  - WinRM: 20–60 сек,
  - SSH: 30–120 сек,
  - SNMP: 30–300 сек (зависит от OID и нагрузки).
- Следите за `/worker/history` и `failure_streak`: при `>=3` система уже помечает проблему как critical.
- Стабилизируйте `source`/формат `message`: это заметно улучшает качество кластеризации.

---

## 8) Диагностика типовых проблем

- **`Unknown asset` при ingest**: сначала создайте asset.
- **WinRM не подключается**:
  - проверьте порт 5985/5986,
  - соответствие transport (NTLM/Basic),
  - TLS/сертификат (`winrm_validate_tls`).
- **SNMP ошибки**:
  - community/version/OID,
  - доступность UDP/161,
  - права на нужные MIB/OID на устройстве.
- **SSH ошибки**:
  - логин/пароль,
  - доступ к `ssh_log_path`,
  - корректность `ssh_metrics_command`.
