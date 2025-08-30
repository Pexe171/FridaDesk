"""Janela principal da aplicação.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtGui import QKeySequence
from PyQt6.QtWidgets import (
    QMainWindow,
    QShortcut,
    QSplitter,
    QTabWidget,
)

from PyQt6.QtCore import Qt

from .widgets.charts_panel import ChartsPanel
from .widgets.console_panel import ConsolePanel
from .widgets.device_panel import DevicePanel
from .widgets.json_viewer import JsonViewer
from .widgets.process_panel import ProcessPanel


class MainWindow(QMainWindow):
    """Janela principal que agrega os painéis."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("FridaDesk")
        self.resize(1024, 768)

        self._build_ui()
        self._configure_theme()

    def _build_ui(self) -> None:
        # Painéis da esquerda (Dispositivos e Processos)
        self.left_splitter = QSplitter(Qt.Orientation.Vertical)
        self.device_panel = DevicePanel()
        self.process_panel = ProcessPanel()
        self.left_splitter.addWidget(self.device_panel)
        self.left_splitter.addWidget(self.process_panel)
        self.left_splitter.setStretchFactor(0, 1)
        self.left_splitter.setStretchFactor(1, 1)

        # Direita superior: Console de Logs com filtro/busca
        self.console_panel = ConsolePanel()

        # Direita inferior: abas de gráficos e JSON
        self.data_tabs = QTabWidget()
        self.charts_panel = ChartsPanel()
        self.json_viewer = JsonViewer()
        self.data_tabs.addTab(self.charts_panel, "Gráficos")
        self.data_tabs.addTab(self.json_viewer, "JSON")

        self.right_splitter = QSplitter(Qt.Orientation.Vertical)
        self.right_splitter.addWidget(self.console_panel)
        self.right_splitter.addWidget(self.data_tabs)
        self.right_splitter.setStretchFactor(0, 1)
        self.right_splitter.setStretchFactor(1, 1)

        # Splitter principal
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_splitter.addWidget(self.left_splitter)
        self.main_splitter.addWidget(self.right_splitter)
        self.main_splitter.setStretchFactor(0, 1)
        self.main_splitter.setStretchFactor(1, 2)

        self.setCentralWidget(self.main_splitter)

    def _configure_theme(self) -> None:
        self._dark = True
        self._light_qss = (
            "QWidget { background-color: #ffffff; color: #000000; }"
            "QTabWidget::pane { border: 1px solid #cccccc; }"
            "QTabBar::tab { padding: 4px; }"
        )
        self._dark_qss = (
            "QWidget { background-color: #2b2b2b; color: #dddddd; }"
            "QTabWidget::pane { border: 1px solid #444444; }"
            "QTabBar::tab { padding: 4px; }"
        )
        self._apply_theme()
        QShortcut(QKeySequence("Ctrl+T"), self, activated=self._toggle_theme)

    def _apply_theme(self) -> None:
        self.setStyleSheet(self._dark_qss if self._dark else self._light_qss)

    def _toggle_theme(self) -> None:
        self._dark = not self._dark
        self._apply_theme()
