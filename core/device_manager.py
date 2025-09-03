"""Gerencia dispositivos conectados via ADB.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import asyncio
from typing import Callable, Dict, List, Tuple

from .models import DeviceInfo, DeviceType


class DeviceManager:
    """Classe responsável por administrar dispositivos.

    O gerenciamento é feito de forma assíncrona, consultando periodicamente o
    comando ``adb devices`` sem bloquear a interface gráfica.
    """

    def __init__(self, interval: float = 2.0) -> None:
        self._interval = interval
        self._devices: Dict[str, DeviceInfo] = {}
        self._remotes: Dict[str, DeviceInfo] = {}
        self._listeners: List[Callable[[List[DeviceInfo]], None]] = []
        self._task: asyncio.Task | None = None
        self._known_ports: Tuple[int, ...] = (5555, 62001, 21503)

    # ------------------------------------------------------------------
    # Controle de execução
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Inicia a tarefa de monitoramento de dispositivos."""

        if self._task is None:
            loop = asyncio.get_event_loop()
            loop.create_task(self._connect_known_emulators())
            self._task = loop.create_task(self._poll_loop())

    def stop(self) -> None:
        """Interrompe o monitoramento de dispositivos."""

        if self._task is not None:
            self._task.cancel()
            self._task = None

    # ------------------------------------------------------------------
    # Manipulação de listeners
    # ------------------------------------------------------------------
    def add_listener(self, callback: Callable[[List[DeviceInfo]], None]) -> None:
        """Registra um callback chamado a cada atualização de dispositivos."""

        self._listeners.append(callback)

    def _emit(self) -> None:
        devices = list(self._devices.values())
        for remote in self._remotes.values():
            if remote.id not in self._devices:
                devices.append(remote)
        for cb in self._listeners:
            cb(devices)

    # ------------------------------------------------------------------
    # Dispositivos remotos
    # ------------------------------------------------------------------
    def add_remote_device(self, endpoint: str, notes: str = "") -> None:
        """Adiciona um endpoint remoto apenas para registro."""

        info = DeviceInfo(
            id=endpoint,
            name=notes or endpoint,
            type=DeviceType.USB,
            status="offline",
        )
        self._remotes[endpoint] = info
        self._emit()

    # ------------------------------------------------------------------
    # Monitoramento
    # ------------------------------------------------------------------
    async def _poll_loop(self) -> None:
        """Loop assíncrono que atualiza a lista de dispositivos."""

        while True:
            await self._update_devices()
            await asyncio.sleep(self._interval)

    async def _update_devices(self) -> None:
        """Reinicia o servidor ADB e atualiza os dispositivos encontrados."""

        try:
            kill_proc = await asyncio.create_subprocess_exec(
                "adb",
                "kill-server",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await kill_proc.communicate()
        except FileNotFoundError:
            pass

        await self._connect_known_emulators()
        seen: Dict[str, DeviceInfo] = {}

        try:
            proc = await asyncio.create_subprocess_exec(
                "adb",
                "devices",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            lines = stdout.decode().splitlines()[1:]
        except FileNotFoundError:
            lines = []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            serial = parts[0]
            status = parts[1] if len(parts) > 1 else "unknown"
            dtype = (
                DeviceType.EMULATOR
                if serial.startswith("emulator-") or serial.startswith("127.0.0.1:")
                else DeviceType.USB
            )
            seen[serial] = DeviceInfo(
                id=serial,
                name=serial,
                type=dtype,
                status=status,
            )

        self._devices = seen
        self._emit()

    async def _connect_known_emulators(self) -> None:
        """Tenta conectar a portas padrão de emuladores."""

        for port in self._known_ports:
            endpoint = f"127.0.0.1:{port}"
            if endpoint in self._devices:
                continue
            try:
                proc = await asyncio.create_subprocess_exec(
                    "adb",
                    "connect",
                    endpoint,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
            except FileNotFoundError:
                break

