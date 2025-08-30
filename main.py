"""Ponto de entrada da aplicação.

Autor: Pexe (Instagram: @David.devloli)
"""

import asyncio
import random
import sys
import time

from PyQt6.QtWidgets import QApplication
from qasync import QEventLoop

from core.event_bus import get_event_bus, publish
from core.models import LogEvent
from ui.main_window import MainWindow


async def simulate_logs() -> None:
    """Gera eventos de log fictícios a cada 100 ms."""

    while True:
        event = LogEvent(
            ts=time.time(),
            level="INFO",
            tag="simulador",
            message=f"Log {random.randint(0, 9999)}",
            raw="",
        )
        publish(event)
        await asyncio.sleep(0.1)


async def main() -> None:
    """Função principal da aplicação."""

    app = QApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    bus = get_event_bus()
    asyncio.create_task(bus.start())

    window = MainWindow(bus)
    window.show()

    asyncio.create_task(simulate_logs())

    with loop:
        await loop.run_forever()


if __name__ == "__main__":
    asyncio.run(main())

