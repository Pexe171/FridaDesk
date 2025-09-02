"""Módulo para exportação de dados.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .models import LogEvent, NetworkEvent

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)


def _timestamp() -> str:
    """Retorna timestamp para nome de arquivo."""

    return datetime.now().strftime("%Y%m%d_%H%M%S")


def export_logs_json(logs: Iterable[LogEvent]) -> Path:
    """Exporta logs em formato JSON."""

    path = LOG_DIR / f"logs_{_timestamp()}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([log.model_dump() for log in logs], fh, ensure_ascii=False, indent=2)
    return path


def export_logs_csv(logs: Iterable[LogEvent]) -> Path:
    """Exporta logs em formato CSV."""

    path = LOG_DIR / f"logs_{_timestamp()}.csv"
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ts", "level", "tag", "message"])
        for log in logs:
            writer.writerow([log.ts, log.level, log.tag, log.message])
    return path


def export_network_json(events: Iterable[NetworkEvent]) -> Path:
    """Exporta eventos de rede em JSON."""

    path = LOG_DIR / f"network_{_timestamp()}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([e.model_dump() for e in events], fh, ensure_ascii=False, indent=2)
    return path


def export_network_har(events: Iterable[NetworkEvent]) -> Path:
    """Exporta eventos de rede em formato HAR simplificado."""

    entries = []
    for e in events:
        entries.append(
            {
                "startedDateTime": datetime.fromtimestamp(e.ts).isoformat(),
                "request": {
                    "method": e.method,
                    "url": e.host,
                    "headers": [],
                    "bodySize": len(e.request),
                },
                "response": {
                    "status": e.status,
                    "statusText": "",
                    "headers": [],
                    "bodySize": e.size,
                },
                "timings": {"send": 0, "wait": 0, "receive": 0},
            }
        )
    har = {"log": {"version": "1.2", "creator": {"name": "FridaDesk"}, "entries": entries}}
    path = LOG_DIR / f"network_{_timestamp()}.har"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(har, fh, ensure_ascii=False, indent=2)
    return path




__all__ = [
    "export_logs_json",
    "export_logs_csv",
    "export_network_json",
    "export_network_har",
]

