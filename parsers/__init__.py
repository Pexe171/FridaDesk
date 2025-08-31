"""Pacote para parsers personalizados.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

_registry: Dict[str, Callable[[str], Any]] = {}
_key_colors: Dict[str, str] = {}


def register_parser(name: str, func: Callable[[str], Any]) -> None:
    """Registra uma função ``func`` para interpretar mensagens."""

    _registry[name] = func


def parse_message(text: str) -> Any:
    """Tenta aplicar parsers registrados para interpretar ``text``."""

    for parser in _registry.values():
        try:
            return parser(text)
        except Exception:
            continue
    return None


def set_key_color(key: str, color: str) -> None:
    """Define a cor associada a ``key``."""

    _key_colors[key] = color


def get_key_color(key: str) -> Optional[str]:
    """Obtém cor registrada para ``key``."""

    return _key_colors.get(key)


def clear_key_colors() -> None:
    """Remove cores previamente registradas."""

    _key_colors.clear()

