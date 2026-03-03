from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from app.models import Event, Severity

LINE_RE = re.compile(
    r"^(?P<ts>\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<session>\S+)\s+ID\s+(?P<thread_id>\d+)\s+"
    r"(?P<kind>Import|Query|Write)\s+(?P<payload>.+)$"
)

SSCC_RE = re.compile(r"\b\d{18}\b")
SCRIPT_RE = re.compile(r'SYS\+SKRIPT;\?:L1\+"([^"]+)"')
USER_RE = re.compile(r'SYS\+LOGIN;!:[^\n]*:L2\+([^+]+)\+\d+\+\d+\+"([^"]+)"\+"([^"]+)"')
ERR_RE = re.compile(r'SYS\+ERRINFO;!:[^\n]*L1\+(\d+)\+\d+\+"([^"]+)"')


def parse_csb_merp_line(line: str) -> dict[str, str] | None:
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    payload = m.group("payload")
    command = payload.split(";", 1)[0].strip() if ";" in payload else payload.strip()
    return {
        "raw": line.strip(),
        "ts": m.group("ts"),
        "session": m.group("session"),
        "thread_id": m.group("thread_id"),
        "kind": m.group("kind"),
        "payload": payload,
        "command": command,
    }


def csb_merp_timestamp_to_datetime(value: str) -> datetime:
    return datetime.strptime(value, "%d.%m.%Y %H:%M:%S.%f")


def detect_merp_severity(payload: str) -> Severity:
    lowered = payload.lower()
    if "sys+errinfo" in lowered or "error" in lowered or "ошиб" in lowered:
        return Severity.warning
    return Severity.info


def line_to_event(asset_id: str, line: str, source: str = "csb_merp_txt") -> Event | None:
    parsed = parse_csb_merp_line(line)
    if not parsed:
        return None
    return Event(
        asset_id=asset_id,
        source=source,
        message=parsed["raw"],
        severity=detect_merp_severity(parsed["payload"]),
        timestamp=csb_merp_timestamp_to_datetime(parsed["ts"]),
    )


def iter_log_files(base_path: str, recursive: bool = True, glob_pattern: str = "*.txt") -> list[Path]:
    root = Path(base_path)
    if not root.exists() or not root.is_dir():
        return []
    if recursive:
        return sorted([p for p in root.rglob(glob_pattern) if p.is_file()])
    return sorted([p for p in root.glob(glob_pattern) if p.is_file()])


def extract_ssccs(text: str) -> list[str]:
    return SSCC_RE.findall(text)


def extract_script(text: str) -> str | None:
    m = SCRIPT_RE.search(text)
    return m.group(1) if m else None


def extract_user(text: str) -> dict[str, str] | None:
    m = USER_RE.search(text)
    if not m:
        return None
    return {"user_id": m.group(1), "first_name": m.group(2), "last_name": m.group(3)}


def extract_error(text: str) -> dict[str, str] | None:
    m = ERR_RE.search(text)
    if not m:
        return None
    return {"code": m.group(1), "message": m.group(2)}
