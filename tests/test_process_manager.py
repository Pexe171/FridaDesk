"""Testes para o ProcessManager.

Autor: Pexe (Instagram: @David.devloli)
"""

import asyncio
from typing import Any

import pytest

from core.process_manager import ProcessManager
from core.models import DeviceInfo, DeviceType


class FakeProcess:
    """Simula o resultado de subprocessos."""

    def __init__(self, output: bytes) -> None:
        self._output = output

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._output, b""


@pytest.mark.asyncio
async def test_list_processes_usb(monkeypatch) -> None:
    """Processos devem ser listados para dispositivos USB."""

    captured: dict[str, Any] = {}

    async def fake_create_subprocess_exec(*cmd, stdout=None, stderr=None):
        captured["cmd"] = cmd
        data = b"""  PID  Name   User\n1234 com.app umUsuario\n"""
        return FakeProcess(data)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    manager = ProcessManager()
    received: list = []
    manager.processes_ready.connect(lambda procs: received.extend(procs))

    device = DeviceInfo(id="ABC123", name="Teste", type=DeviceType.USB)
    await manager.list_processes(device)

    assert captured["cmd"] == ("frida-ps", "-Uai")
    assert len(received) == 1
    assert received[0].pid == 1234
    assert received[0].name == "com.app"
    assert received[0].user == "umUsuario"


@pytest.mark.asyncio
async def test_list_processes_remote(monkeypatch) -> None:
    """Processos devem ser listados para dispositivos remotos."""

    captured: dict[str, Any] = {}

    async def fake_create_subprocess_exec(*cmd, stdout=None, stderr=None):
        captured["cmd"] = cmd
        data = b"""  PID  Name   User\n4321 remoto.app outroUsuario\n"""
        return FakeProcess(data)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    manager = ProcessManager()
    received: list = []
    manager.processes_ready.connect(lambda procs: received.extend(procs))

    device = DeviceInfo(id="10.0.0.1:1234", name="Remoto", type=DeviceType.USB)
    await manager.list_processes(device)

    assert captured["cmd"] == ("frida-ps", "-Rai")
    assert len(received) == 1
    assert received[0].pid == 4321
    assert received[0].name == "remoto.app"
    assert received[0].user == "outroUsuario"
