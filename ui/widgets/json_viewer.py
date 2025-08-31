"""Visualizador de JSON.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import json
from typing import Any

from PyQt6.QtWidgets import (
    QPlainTextEdit,
    QStackedLayout,
    QTreeView,
    QWidget,
)
from PyQt6.QtGui import QStandardItem, QStandardItemModel

from core.event_bus import EventBus
from core.models import LogEvent
from parsers import parse_message


class JsonViewer(QWidget):
    """Exibe objetos JSON em árvore com fallback para texto cru."""

    def __init__(self, bus: EventBus) -> None:
        super().__init__()
        self._build_ui()
        bus.log_event.connect(self._handle_log)

    def _build_ui(self) -> None:
        self._tree = QTreeView()
        self._model = QStandardItemModel()
        self._model.setHorizontalHeaderLabels(["Chave", "Valor"])
        self._tree.setModel(self._model)

        self._raw = QPlainTextEdit()
        self._raw.setReadOnly(True)

        self._stack = QStackedLayout(self)
        self._stack.addWidget(self._tree)
        self._stack.addWidget(self._raw)

    def _handle_log(self, event: LogEvent) -> None:
        text = event.message.strip()
        data: Any = None
        try:
            data = json.loads(text)
        except Exception:
            data = parse_message(text)

        if isinstance(data, (dict, list)):
            self._show_json(data)
        else:
            self._show_raw(text)

    def _show_raw(self, text: str) -> None:
        self._raw.setPlainText(text)
        self._stack.setCurrentWidget(self._raw)

    def _show_json(self, data: Any) -> None:
        self._model.removeRows(0, self._model.rowCount())
        self._add_items(self._model.invisibleRootItem(), data)
        self._tree.expandAll()
        self._stack.setCurrentWidget(self._tree)

    def _add_items(self, parent: QStandardItem, data: Any) -> None:
        if isinstance(data, dict):
            for key, value in data.items():
                key_item = QStandardItem(str(key))
                parent.appendRow([key_item, QStandardItem("")])
                self._add_items(key_item, value)
        elif isinstance(data, list):
            for idx, value in enumerate(data):
                key_item = QStandardItem(str(idx))
                parent.appendRow([key_item, QStandardItem("")])
                self._add_items(key_item, value)
        else:
            parent.setChild(parent.rowCount() - 1, 1, QStandardItem(str(data)))

