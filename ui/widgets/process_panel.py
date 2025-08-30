"""Painel de processos.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtWidgets import QWidget


class ProcessPanel(QWidget):
    """Exibe processos ativos."""

    def __init__(self) -> None:
        super().__init__()
