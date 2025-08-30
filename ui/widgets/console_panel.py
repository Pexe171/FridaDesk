"""Painel de console.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtWidgets import QWidget


class ConsolePanel(QWidget):
    """Exibe logs e mensagens."""

    def __init__(self) -> None:
        super().__init__()
