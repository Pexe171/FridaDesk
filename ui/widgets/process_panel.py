"""Painel de processos.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QWidget,
    QLabel,
    QHBoxLayout,
)

from core.process_manager import ProcessManager
from core.models import ProcessInfo

if TYPE_CHECKING:
    from .device_panel import DevicePanel


class ProcessPanel(QWidget):
    """Exibe processos ativos."""

    def __init__(self) -> None:
        super().__init__()

        self._manager = ProcessManager()
        self._manager.processes_ready.connect(self._refresh)

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(8, 8, 8, 8)
        self._list = QListWidget()
        self._list.setUniformItemSizes(True)
        self._list.currentTextChanged.connect(self._on_current_changed)
        self._list.setStyleSheet(
            """
QListWidget::item { padding: 4px; }
QListWidget::item:hover { background-color: #002b36; }
QListWidget::item:selected { background-color: #003c50; border: 1px solid #00ffff; }
"""
        )
        layout.addWidget(self._list)

        self._current = ""
        self._desired = "com.example.secureapp (PID: 1337)"
        self._device_panel: DevicePanel | None = None

    # ------------------------------------------------------------------
    # Integração com DevicePanel
    # ------------------------------------------------------------------
    def set_device_panel(self, panel: "DevicePanel") -> None:
        self._device_panel = panel
        panel._list.currentTextChanged.connect(self._device_changed)

    def _device_changed(self, text: str) -> None:
        if not self._device_panel:
            return
        if "(" in text and text.endswith(")"):
            dev_id = text.split("(")[-1].rstrip(")")
        else:
            dev_id = text
        manager = self._device_panel._manager
        dev = manager._devices.get(dev_id) or manager._remotes.get(dev_id)
        if dev:
            asyncio.create_task(self._manager.list_processes(dev))

    # ------------------------------------------------------------------
    # Atualização da lista
    # ------------------------------------------------------------------
    def _refresh(self, processes: list[ProcessInfo]) -> None:
        self._list.clear()
        for proc in processes:
            text = f"{proc.name} (PID: {proc.pid})"
            item = QListWidgetItem(text)
            item.setToolTip(proc.user)
            badge_widget = QWidget()
            h = QHBoxLayout(badge_widget)
            h.setContentsMargins(4, 2, 4, 2)
            h.setSpacing(6)
            name_lbl = QLabel(proc.name)
            pid_lbl = QLabel(f"PID: {proc.pid}")
            status_lbl = QLabel("ativo")
            for lbl in (pid_lbl, status_lbl):
                lbl.setStyleSheet(
                    "background-color:#00ffff;color:#000;padding:1px 3px;border-radius:3px;"
                )
            h.addWidget(name_lbl)
            h.addWidget(pid_lbl)
            h.addWidget(status_lbl)
            h.addStretch()
            self._list.addItem(item)
            self._list.setItemWidget(item, badge_widget)
            item.setSizeHint(badge_widget.sizeHint())
        if self._desired:
            self.set_current_process(self._desired)

    def _on_current_changed(self, text: str) -> None:
        self._current = text

    def current_process(self) -> str:
        return self._current

    def set_current_process(self, name: str) -> None:
        for i in range(self._list.count()):
            if self._list.item(i).text() == name:
                self._list.setCurrentRow(i)
                self._current = name
                break

    def load_state(self, settings: dict) -> None:
        self._desired = settings.get("last_process", "")

    def save_state(self, settings: dict) -> None:
        settings["last_process"] = self._current
