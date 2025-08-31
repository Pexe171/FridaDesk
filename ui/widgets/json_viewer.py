"""Visualizador de JSON.

Autor: Pexe (Instagram: @David.devloli)
"""

import json
from typing import Any

from PyQt6.QtWidgets import (
    QTreeView,
    QVBoxLayout,
    QWidget,
    QPlainTextEdit,
)
from PyQt6.QtGui import QStandardItemModel, QStandardItem

from core.event_bus import EventBus
from core.models import LogEvent


class JsonViewer(QWidget):
    """Exibe objetos JSON em árvore, com fallback para texto cru."""

    def __init__(self, bus: EventBus) -> None:
        super().__init__()
        self._bus = bus

        layout = QVBoxLayout(self)
        self._tree = QTreeView()
        self._model = QStandardItemModel()
        self._model.setHorizontalHeaderLabels(["Chave", "Valor"])
        self._tree.setModel(self._model)

        self._raw = QPlainTextEdit()
        self._raw.setReadOnly(True)

        layout.addWidget(self._tree)
        layout.addWidget(self._raw)
        self._raw.hide()

        self._bus.log_event.connect(self._handle_log)

    def _handle_log(self, event: LogEvent) -> None:
        self.display_text(event.message)

    def display_text(self, text: str) -> None:
        """Tenta interpretar ``text`` como JSON e exibir em árvore."""

        try:
            data = json.loads(text)
        except Exception:
            self._tree.hide()
            self._raw.show()
            self._raw.setPlainText(text)
            return

        self._raw.hide()
        self._tree.show()
        self._model.removeRows(0, self._model.rowCount())
        self._populate(self._model.invisibleRootItem(), data)

    def _populate(self, parent: QStandardItem, value: Any) -> None:
        if isinstance(value, dict):
            for key, val in value.items():
                key_item = QStandardItem(str(key))
                val_item = QStandardItem("" if isinstance(val, (dict, list)) else str(val))
                parent.appendRow([key_item, val_item])
                self._populate(key_item, val)
        elif isinstance(value, list):
            for idx, val in enumerate(value):
                key_item = QStandardItem(str(idx))
                val_item = QStandardItem("" if isinstance(val, (dict, list)) else str(val))
                parent.appendRow([key_item, val_item])
                self._populate(key_item, val)
