"""Painel de console.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtWidgets import (
    QLineEdit,
    QPlainTextEdit,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.event_bus import EventBus
from core.models import LogEvent


class ConsolePanel(QWidget):
    """Exibe logs e mensagens."""

    def __init__(self, bus: EventBus) -> None:
        super().__init__()
        self._bus = bus
        self._build_ui()
        self._bus.log_event.connect(self._append_log)

    def _build_ui(self) -> None:
        tabs = QTabWidget()

        self._logs_widget = QPlainTextEdit()
        self._logs_widget.setPlaceholderText("Logs aparecerão aqui...")
        tabs.addTab(self._logs_widget, "Console")

        filter_widget = QWidget()
        filter_layout = QVBoxLayout(filter_widget)
        filter_input = QLineEdit()
        filter_input.setPlaceholderText("Filtrar/Buscar logs")
        filter_layout.addWidget(filter_input)
        filter_layout.addStretch(1)
        tabs.addTab(filter_widget, "Filtro/Busca")

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)

    def _append_log(self, event: LogEvent) -> None:
        """Acrescenta um evento de log no painel de texto."""

        self._logs_widget.appendPlainText(
            f"[{event.level}] {event.tag}: {event.message}"
        )
