"""Painel de processos.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget


class ProcessPanel(QWidget):
    """Exibe processos ativos."""

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        placeholder = QLabel("Painel de Processos")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(placeholder)
        self._current = ""

    def current_process(self) -> str:
        return self._current

    def set_current_process(self, name: str) -> None:
        self._current = name

    def load_state(self, settings: dict) -> None:
        self.set_current_process(settings.get("last_process", ""))

    def save_state(self, settings: dict) -> None:
        settings["last_process"] = self._current
