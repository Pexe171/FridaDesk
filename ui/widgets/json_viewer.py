"""Visualizador de JSON.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtWidgets import QWidget


class JsonViewer(QWidget):
    """Exibe dados JSON formatados."""

    def __init__(self) -> None:
        super().__init__()
