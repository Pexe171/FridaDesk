"""Visualizador de JSON.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget


class JsonViewer(QWidget):
    """Exibe dados JSON formatados."""

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        placeholder = QLabel("Visualizador JSON")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(placeholder)
