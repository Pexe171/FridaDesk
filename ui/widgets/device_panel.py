"""Painel de dispositivos.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import (
    QInputDialog,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QStyle,
    QVBoxLayout,
    QWidget,
)

from core.device_manager import DeviceManager
from core.models import DeviceInfo, DeviceType


class DevicePanel(QWidget):
    """Exibe e gerencia dispositivos conectados via ADB."""

    def __init__(self) -> None:
        super().__init__()

        self._manager = DeviceManager()
        self._manager.add_listener(self._refresh)
        self._manager.start()

        layout = QVBoxLayout(self)

        self._add_btn = QPushButton("Adicionar dispositivo remoto (Android)")
        self._add_btn.clicked.connect(self._add_remote_device)
        layout.addWidget(self._add_btn)

        self._list = QListWidget()
        self._list.setUniformItemSizes(True)
        self._list.currentTextChanged.connect(self._on_current_changed)
        layout.addWidget(self._list)
        self._current = ""
        self._desired = ""

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------
    def _add_remote_device(self) -> None:
        endpoint, ok = QInputDialog.getText(
            self,
            "Adicionar dispositivo remoto",
            "Endpoint ADB (ex.: 192.168.0.10:5555)",
        )
        if not ok or not endpoint:
            return
        notes, _ = QInputDialog.getText(
            self,
            "Notas",
            "Notas adicionais (opcional)",
        )
        self._manager.add_remote_device(endpoint, notes)

    def _refresh(self, devices: list[DeviceInfo]) -> None:
        self._list.clear()
        for dev in devices:
            item = QListWidgetItem(f"{dev.name} ({dev.id})")
            item.setToolTip(dev.status or "")
            color = QColor("green") if dev.status == "device" else QColor("gray")
            item.setForeground(QBrush(color))

            icon = (
                self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
                if dev.type == DeviceType.EMULATOR
                else self.style().standardIcon(QStyle.StandardPixmap.SP_DriveHDIcon)
            )
            item.setIcon(icon)
            self._list.addItem(item)
        if self._desired:
            self.set_current_device(self._desired)

    def _on_current_changed(self, text: str) -> None:
        self._current = text

    def set_current_device(self, name: str) -> None:
        for i in range(self._list.count()):
            if self._list.item(i).text() == name:
                self._list.setCurrentRow(i)
                self._current = name
                break

    def load_state(self, settings: dict) -> None:
        self._desired = settings.get("last_device", "")

    def save_state(self, settings: dict) -> None:
        settings["last_device"] = self._current

