"""Integração central com Frida.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import frida  # type: ignore[import]

from .event_bus import publish
from .models import LogEvent


class FridaManager:
    """Gerencia a comunicação com processos via Frida."""

    def __init__(self) -> None:
        self._session: Any | None = None
        self._script: Any | None = None

    # ------------------------------------------------------------------
    # Conexão
    # ------------------------------------------------------------------
    def attach(self, target: int | str) -> None:
        """Anexa ao processo especificado por PID ou nome."""

        self._session = frida.attach(target)

    def detach(self) -> None:
        """Desanexa do processo atual e descarrega o script."""

        if self._script is not None:
            try:
                self._script.unload()
            except Exception:  # pragma: no cover - falhas ao descarregar
                pass
            self._script = None
        if self._session is not None:
            try:
                self._session.detach()
            except Exception:  # pragma: no cover - falhas ao desanexar
                pass
            self._session = None

    # ------------------------------------------------------------------
    # Scripts
    # ------------------------------------------------------------------
    def inject_script_from_text(self, source: str) -> None:
        """Carrega e injeta um script a partir de ``source``."""

        if self._session is None:
            raise RuntimeError("Sessão não iniciada")

        self._script = self._session.create_script(source)
        self._script.on("message", self._on_message)
        self._script.load()

    def inject_script_from_file(self, path: str | Path) -> None:
        """Lê um arquivo e injeta seu conteúdo como script."""

        code = Path(path).read_text(encoding="utf-8")
        self.inject_script_from_text(code)

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------
    def _on_message(self, message: Any, data: Any) -> None:
        payload = (
            message.get("payload") if isinstance(message, dict) else message
        )
        event = LogEvent(
            ts=time.time(),
            level="info",
            tag="frida",
            message=str(payload),
            raw=str(message),
        )
        publish(event)
