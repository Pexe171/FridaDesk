"""Painel de gráficos.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget


class ChartsPanel(QWidget):
    """Exibe gráficos utilizando pyqtgraph."""

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        placeholder = QLabel("Gráficos")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(placeholder)
