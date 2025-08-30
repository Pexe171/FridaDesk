"""Painel de console.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtWidgets import (
    QLineEdit,
    QPlainTextEdit,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


class ConsolePanel(QWidget):
    """Exibe logs e mensagens."""

    def __init__(self) -> None:
        super().__init__()
        self._build_ui()

    def _build_ui(self) -> None:
        tabs = QTabWidget()

        logs_widget = QPlainTextEdit()
        logs_widget.setPlaceholderText("Logs aparecerão aqui...")
        tabs.addTab(logs_widget, "Console")

        filter_widget = QWidget()
        filter_layout = QVBoxLayout(filter_widget)
        filter_input = QLineEdit()
        filter_input.setPlaceholderText("Filtrar/Buscar logs")
        filter_layout.addWidget(filter_input)
        filter_layout.addStretch(1)
        tabs.addTab(filter_widget, "Filtro/Busca")

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
