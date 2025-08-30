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
