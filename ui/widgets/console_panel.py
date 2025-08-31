"""Painel de console.

Autor: Pexe (Instagram: @David.devloli)
"""

from datetime import datetime
from typing import List

from PyQt6.QtGui import QKeySequence
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QShortcut,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.event_bus import EventBus
from core.models import LogEvent
from core.exporters import export_logs_csv, export_logs_json


class ConsolePanel(QWidget):
    """Exibe logs e mensagens em uma tabela."""

    def __init__(self, bus: EventBus) -> None:
        super().__init__()
        self._bus = bus
        self._paused = False
        self._logs: List[LogEvent] = []
        self._build_ui()
        self._bus.log_event.connect(self._append_log)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        controls_layout = QHBoxLayout()
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("Filtrar/Buscar logs")
        self._filter_input.setToolTip("Buscar texto nos logs (Ctrl+F)")
        self._filter_input.textChanged.connect(self._apply_filter)
        controls_layout.addWidget(self._filter_input)

        style = self.style()
        self._pause_btn = QPushButton("Pausar")
        self._pause_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_MediaPause))
        self._pause_btn.setToolTip("Pausar/retomar captura de logs (F5)")
        self._pause_btn.setCheckable(True)
        self._pause_btn.toggled.connect(self._toggle_pause)
        controls_layout.addWidget(self._pause_btn)

        clear_btn = QPushButton("Limpar")
        clear_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_DialogResetButton))
        clear_btn.setToolTip("Limpar tabela de logs")
        clear_btn.clicked.connect(self._clear)
        controls_layout.addWidget(clear_btn)

        copy_btn = QPushButton("Copiar seleção")
        copy_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_DialogOpenButton))
        copy_btn.setToolTip("Copiar linhas selecionadas")
        copy_btn.clicked.connect(self._copy_selection)
        controls_layout.addWidget(copy_btn)

        export_btn = QPushButton("Exportar")
        export_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton))
        export_btn.setToolTip("Exportar logs (Ctrl+E)")
        export_btn.clicked.connect(self._export)
        controls_layout.addWidget(export_btn)

        QShortcut(QKeySequence("Ctrl+F"), self, activated=self._filter_input.setFocus)
        QShortcut(QKeySequence("Ctrl+E"), self, activated=self._export)

        layout.addLayout(controls_layout)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Tempo", "Nível", "Tag", "Mensagem"])
        self._table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self._table)

    # ------------------------------------------------------------------
    # Estado
    # ------------------------------------------------------------------
    def load_state(self, settings: dict) -> None:
        self._filter_input.setText(settings.get("log_filter", ""))
        self._pause_btn.setChecked(settings.get("log_paused", False))

    def save_state(self, settings: dict) -> None:
        settings["log_filter"] = self._filter_input.text()
        settings["log_paused"] = self._paused

    def _append_log(self, event: LogEvent) -> None:
        """Acrescenta um evento de log na tabela."""

        self._logs.append(event)
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
        self._pause_btn.setText("Retomar" if checked else "Pausar")
        self._status("Coleta pausada" if checked else "Coleta retomada")

    def _clear(self) -> None:
        self._table.setRowCount(0)
        self._status("Logs limpos")

    def _filtered_logs(self) -> List[LogEvent]:
        text = self._filter_input.text().lower()
        if not text:
            return list(self._logs)
        result: List[LogEvent] = []
        for e in self._logs:
            if (
                text in datetime.fromtimestamp(e.ts).strftime("%H:%M:%S").lower()
                or text in e.level.lower()
                or text in e.tag.lower()
                or text in e.message.lower()
            ):
                result.append(e)
        return result

    def _export(self) -> None:
        logs = self._filtered_logs()
        if not logs:
            QMessageBox.information(self, "Exportação", "Nenhum log para exportar.")
            return
        json_path = export_logs_json(logs)
        csv_path = export_logs_csv(logs)
        QMessageBox.information(
            self,
            "Exportação",
            f"Logs salvos em:\n{json_path}\n{csv_path}",
        )
        self._status("Logs exportados")

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
        self._status("Logs copiados para a área de transferência")

    def _status(self, text: str) -> None:
        win = self.window()
        if hasattr(win, "statusBar"):
            win.statusBar().showMessage(text, 3000)
