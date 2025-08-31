"""Pacote para parsers personalizados.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

from typing import Any, Callable, Dict

_registry: Dict[str, Callable[[str], Any]] = {}


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

