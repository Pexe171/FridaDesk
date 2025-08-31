"""Barramento assíncrono de eventos utilizando sinais Qt.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import asyncio
from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal

from .models import LogEvent, MetricSample, NetworkEvent


class EventBus(QObject):
    """Centraliza a distribuição de eventos para a interface."""

    log_event = pyqtSignal(object)
    metric_sample = pyqtSignal(object)
    network_event = pyqtSignal(object)

    def __init__(self) -> None:
        super().__init__()
        self._queue: asyncio.Queue[Any] = asyncio.Queue()

    async def start(self) -> None:
        """Consome eventos da fila e emite sinais correspondentes."""

        while True:
            event = await self._queue.get()
            if isinstance(event, LogEvent):
                self.log_event.emit(event)
            elif isinstance(event, MetricSample):
                self.metric_sample.emit(event)
            elif isinstance(event, NetworkEvent):
                self.network_event.emit(event)
            self._queue.task_done()

    def publish(self, event: Any) -> None:
        """Publica um novo evento no barramento."""

        self._queue.put_nowait(event)


_bus = EventBus()


def get_event_bus() -> EventBus:
    """Retorna a instância global do barramento."""

    return _bus


def publish(event: Any) -> None:
    """API simples para publicar eventos sem acessar o bus diretamente."""

    _bus.publish(event)

