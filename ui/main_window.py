"""Janela principal da aplicação.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtWidgets import QMainWindow


class MainWindow(QMainWindow):
    """Janela principal que agrega os painéis."""

    def __init__(self) -> None:
        super().__init__()
