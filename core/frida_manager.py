"""Integração central com Frida.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import frida  # type: ignore[import]

from .event_bus import get_event_bus, publish
from .models import LogEvent
from .codeshare import download_codeshare_script


class FridaManager:
    """Gerencia a comunicação com processos via Frida."""

    def __init__(self) -> None:
        self._session: Any | None = None
        self._script: Any | None = None
        self._bus = get_event_bus()
        self._bus.frida_send_to_script.connect(self.send_message)

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

    def inject_script_from_codeshare(self, identifier: str) -> None:
        """Baixa um snippet do CodeShare e o injeta."""

        code = download_codeshare_script(identifier)
        self.inject_script_from_text(code)

    def send_message(self, payload: Any) -> None:
        """Envia ``payload`` ao script injetado via ``post``."""

        if self._script is None:
            raise RuntimeError("Script não injetado")
        self._script.post(payload)

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------
    def _on_message(self, message: Any, data: Any) -> None:
        payload = (
            message.get("payload") if isinstance(message, dict) else message
        )
        self._bus.frida_message_received.emit(payload)
        event = LogEvent(
            ts=time.time(),
            level="info",
            tag="frida",
            message=str(payload),
            raw=str(message),
        )
        publish(event)
