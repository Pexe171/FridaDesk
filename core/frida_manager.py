"""Integração central com Frida.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any
from urllib.request import urlopen

import frida  # type: ignore[import]

from .event_bus import get_event_bus, publish
from .models import LogEvent


CODESHARE_RE = re.compile(r"--codeshare\s+([^\s]+)")


def parse_codeshare_slug(text: str) -> str | None:
    """Extrai o *slug* de um comando do CodeShare.

    Aceita entradas nos formatos:
    ``$ frida --codeshare autor/script -f alvo``
    ``frida --codeshare autor/script -f alvo``
    ``autor/script``
    """

    cleaned = text.strip()
    if cleaned.startswith("$"):
        cleaned = cleaned[1:].strip()
    match = CODESHARE_RE.search(cleaned)
    if match:
        return match.group(1)
    if "/" in cleaned and " " not in cleaned:
        return cleaned
    return None


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
    def fetch_codeshare_script(self, slug_or_command: str) -> str:
        """Obtém o código de um script hospedado no CodeShare."""

        slug = parse_codeshare_slug(slug_or_command)
        if not slug:
            raise ValueError("Comando CodeShare inválido")
        url = f"https://codeshare.frida.re/@{slug}.js"
        with urlopen(url) as resp:  # pragma: no cover - IO externo
            return resp.read().decode("utf-8")

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
