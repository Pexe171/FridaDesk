"""Painel de dispositivos.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtWidgets import QWidget


class DevicePanel(QWidget):
    """Exibe informações sobre dispositivos conectados."""

    def __init__(self) -> None:
        super().__init__()
