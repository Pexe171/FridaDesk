"""Pacote para parsers personalizados.

Autor: Pexe (Instagram: @David.devloli)
"""

from typing import Any, Callable, Dict

_PARSERS: Dict[str, Callable[[bytes], Any]] = {}


def register_parser(name: str, func: Callable[[bytes], Any]) -> None:
    """Registra um ``func`` para decodificar dados identificados por ``name``."""

    _PARSERS[name] = func


def parse(name: str, data: bytes) -> Any:
    """Executa o parser registrado para ``name``."""

    if name not in _PARSERS:
        raise KeyError(f"Parser não registrado: {name}")
    return _PARSERS[name](data)


__all__ = ["register_parser", "parse"]

