"""Painel de gráficos.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtWidgets import QWidget


class ChartsPanel(QWidget):
    """Exibe gráficos utilizando pyqtgraph."""

    def __init__(self) -> None:
        super().__init__()
