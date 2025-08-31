"""Gerenciamento de configurações persistentes.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


SETTINGS_FILE = Path(__file__).resolve().parent.parent / "settings.json"

DEFAULTS: Dict[str, Any] = {
    "autor": "Pexe",
    "instagram": "David.devloli",
    "window": {"size": [1024, 768], "pos": [100, 100]},
    "theme": "dark",
    "last_device": "",
    "last_process": "",
    "log_filter": "",
    "log_paused": False,
    "metrics_active": False,
}


def load_settings() -> Dict[str, Any]:
    """Carrega configurações do arquivo JSON."""

    data: Dict[str, Any] = {}
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            data = {}
    merged = DEFAULTS.copy()
    for key, value in data.items():
        if isinstance(value, dict) and key in merged:
            merged[key].update(value)
        else:
            merged[key] = value
    return merged


def save_settings(data: Dict[str, Any]) -> None:
    """Salva configurações no arquivo JSON."""

    SETTINGS_FILE.parent.mkdir(exist_ok=True)
    with open(SETTINGS_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=4)


__all__ = ["load_settings", "save_settings"]

