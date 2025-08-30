"""Painel de dispositivos.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget


class DevicePanel(QWidget):
    """Exibe informações sobre dispositivos conectados."""

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        placeholder = QLabel("Painel de Dispositivos")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(placeholder)
