"""Gerencia listagem de processos utilizando frida-ps.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import asyncio
from typing import List

from PyQt6.QtCore import QObject, pyqtSignal

from .models import DeviceInfo, ProcessInfo


class ProcessManager(QObject):
    """Executa frida-ps para obter processos ou aplicativos instalados."""

    processes_ready = pyqtSignal(object)

    async def list_processes(self, device: DeviceInfo) -> None:
        """Lista processos para o ``device`` fornecido e emite um sinal."""

        if ":" in device.id:
            cmd = ["frida-ps", "-Rai"]
        else:
            cmd = ["frida-ps", "-Uai"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            lines = stdout.decode().splitlines()[1:]
        except FileNotFoundError:
            lines = []

        processes: List[ProcessInfo] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            try:
                pid = int(parts[0])
            except (ValueError, IndexError):
                continue
            user = parts[-1] if len(parts) > 2 else ""
            name = " ".join(parts[1:-1]) if len(parts) > 2 else parts[1] if len(parts) > 1 else ""
            processes.append(ProcessInfo(pid=pid, name=name, user=user))

        self.processes_ready.emit(processes)
