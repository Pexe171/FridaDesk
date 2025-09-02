"""Testes para o FridaManager.

Autor: Pexe (Instagram: @David.devloli)
"""

from pathlib import Path
import types

import importlib
import sys

from core import event_bus
from core.models import LogEvent


class FakeScript:
    """Script falso que dispara uma mensagem ao carregar."""

    def __init__(self, payload: str) -> None:
        self._payload = payload
        self._cb = None

    def on(self, _event: str, callback) -> None:  # pragma: no cover - assinatura simplificada
        self._cb = callback

    def load(self) -> None:
        if self._cb:
            self._cb({"type": "send", "payload": self._payload}, None)

    def unload(self) -> None:  # pragma: no cover - sem efeitos
        pass


class FakeSession:
    """Sessão falsa utilizada para testes."""

    def __init__(self) -> None:
        self.detached = False

    def create_script(self, code: str) -> FakeScript:
        payload = code.split("'")[1] if "'" in code else code
        return FakeScript(payload)

    def detach(self) -> None:
        self.detached = True


def make_fake_frida_module() -> types.ModuleType:
    """Cria um módulo ``frida`` simplificado."""

    module = types.ModuleType("frida")
    module.attach = lambda target: FakeSession()
    return module


def get_manager(monkeypatch):
    fake = make_fake_frida_module()
    monkeypatch.setitem(sys.modules, "frida", fake)
    import core.frida_manager as fm
    importlib.reload(fm)
    return fm.FridaManager()


def test_inject_script_from_text(monkeypatch) -> None:
    eventos: list[LogEvent] = []
    monkeypatch.setattr(event_bus, "publish", lambda e: eventos.append(e))
    manager = get_manager(monkeypatch)
    manager.attach(1234)
    manager.inject_script_from_text("send('ola')")

    assert len(eventos) == 1
    assert eventos[0].message == "ola"

    manager.detach()
    assert manager._session is None


def test_inject_script_from_file(monkeypatch, tmp_path: Path) -> None:
    eventos: list[LogEvent] = []
    monkeypatch.setattr(event_bus, "publish", lambda e: eventos.append(e))
    manager = get_manager(monkeypatch)

    arquivo = tmp_path / "script.js"
    arquivo.write_text("send('arquivo')", encoding="utf-8")

    manager.attach("nome")
    manager.inject_script_from_file(arquivo)

    assert len(eventos) == 1
    assert eventos[0].message == "arquivo"

