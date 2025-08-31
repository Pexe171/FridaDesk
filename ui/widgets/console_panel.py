"""Painel de console.

Autor: Pexe (Instagram: @David.devloli)
"""

from datetime import datetime
from typing import List

from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.event_bus import EventBus
from core.models import LogEvent


class ConsolePanel(QWidget):
    """Exibe logs e mensagens em uma tabela."""

    def __init__(self, bus: EventBus) -> None:
        super().__init__()
        self._bus = bus
        self._paused = False
        self._build_ui()
        self._bus.log_event.connect(self._append_log)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        controls_layout = QHBoxLayout()
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("Filtrar/Buscar logs")
        self._filter_input.textChanged.connect(self._apply_filter)
        controls_layout.addWidget(self._filter_input)

        self._pause_btn = QPushButton("Pausar")
        self._pause_btn.setCheckable(True)
        self._pause_btn.toggled.connect(self._toggle_pause)
        controls_layout.addWidget(self._pause_btn)

        clear_btn = QPushButton("Limpar")
        clear_btn.clicked.connect(self._clear)
        controls_layout.addWidget(clear_btn)

        copy_btn = QPushButton("Copiar seleção")
        copy_btn.clicked.connect(self._copy_selection)
        controls_layout.addWidget(copy_btn)

        layout.addLayout(controls_layout)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Tempo", "Nível", "Tag", "Mensagem"])
        self._table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self._table)

    def _append_log(self, event: LogEvent) -> None:
        """Acrescenta um evento de log na tabela."""

        row = self._table.rowCount()
        self._table.insertRow(row)
        ts_str = datetime.fromtimestamp(event.ts).strftime("%H:%M:%S")
        self._table.setItem(row, 0, QTableWidgetItem(ts_str))
        self._table.setItem(row, 1, QTableWidgetItem(event.level))
        self._table.setItem(row, 2, QTableWidgetItem(event.tag))
        self._table.setItem(row, 3, QTableWidgetItem(event.message))
        self._apply_filter(self._filter_input.text())
        if not self._paused:
            self._table.scrollToBottom()

    def _apply_filter(self, text: str) -> None:
        lowered = text.lower()
        for row in range(self._table.rowCount()):
            match = False
            if lowered:
                for col in range(self._table.columnCount()):
                    item = self._table.item(row, col)
                    if item and lowered in item.text().lower():
                        match = True
                        break
            else:
                match = True
            self._table.setRowHidden(row, not match)

    def _toggle_pause(self, checked: bool) -> None:
        self._paused = checked

    def _clear(self) -> None:
        self._table.setRowCount(0)

    def _copy_selection(self) -> None:
        ranges = self._table.selectedRanges()
        if not ranges:
            return
        lines: List[str] = []
        for r in ranges:
            for row in range(r.topRow(), r.bottomRow() + 1):
                parts = []
                for col in range(self._table.columnCount()):
                    item = self._table.item(row, col)
                    parts.append(item.text() if item else "")
                lines.append("\t".join(parts))
        QApplication.clipboard().setText("\n".join(lines))
