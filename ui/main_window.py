"""Janela principal da aplicação.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtGui import QAction, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QMainWindow,
    QSplitter,
    QTabWidget,
)

from PyQt6.QtCore import Qt

from core.event_bus import EventBus
from core.settings import load_settings, save_settings

from core.frida_manager import FridaManager
from .widgets.charts_panel import ChartsPanel
from .widgets.console_panel import ConsolePanel
from .widgets.device_panel import DevicePanel
from .widgets.json_viewer import JsonViewer
from .widgets.process_panel import ProcessPanel
from .widgets.network_panel import NetworkPanel
from .widgets.script_editor_panel import ScriptEditorPanel


class MainWindow(QMainWindow):
    """Janela principal que agrega os painéis."""

    def __init__(self, bus: EventBus) -> None:
        super().__init__()
        self._bus = bus
        self._frida = FridaManager()
        self._settings = load_settings()
        self.setWindowTitle("FridaDesk")
        size = self._settings.get("window", {}).get("size", [1024, 768])
        pos = self._settings.get("window", {}).get("pos", [100, 100])
        self.resize(*size)
        self.move(*pos)

        self._build_ui()
        self._configure_theme()
        self._restore_state()
        self.statusBar().showMessage("Pronto")
        QShortcut(QKeySequence("F5"), self, activated=self._toggle_collection)

    def _build_ui(self) -> None:
        # Painéis da esquerda (Dispositivos e Processos)
        self.left_splitter = QSplitter(Qt.Orientation.Vertical)
        self.device_panel = DevicePanel()
        self.process_panel = ProcessPanel()
        self.process_panel.set_device_panel(self.device_panel)
        self.left_splitter.addWidget(self.device_panel)
        self.left_splitter.addWidget(self.process_panel)
        self.left_splitter.setStretchFactor(0, 1)
        self.left_splitter.setStretchFactor(1, 1)

        # Direita superior: Console de Logs com filtro/busca
        self.console_panel = ConsolePanel(self._bus)

        # Direita inferior: abas de gráficos, JSON e rede
        self.data_tabs = QTabWidget()
        self.charts_panel = ChartsPanel(self._bus)
        self.json_viewer = JsonViewer(self._bus)
        self.network_panel = NetworkPanel(self._bus)
        self.script_panel = ScriptEditorPanel(self._frida)
        self.script_panel.set_process_panel(self.process_panel)
        self.data_tabs.addTab(self.charts_panel, "Gráficos")
        self.data_tabs.addTab(self.json_viewer, "JSON")
        self.data_tabs.addTab(self.network_panel, "Rede")
        self.data_tabs.addTab(self.script_panel, "Scripts")

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

        # Menu para plugins
        self.plugins_menu = self.menuBar().addMenu("Plugins")

    def add_plugin_menu_action(self, title: str, callback):
        action = QAction(title, self)
        action.triggered.connect(callback)
        self.plugins_menu.addAction(action)
        return action

    def _configure_theme(self) -> None:
        self._dark = self._settings.get("theme", "dark") == "dark"
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
        self.statusBar().showMessage("Tema escuro" if self._dark else "Tema claro", 3000)

    def _toggle_collection(self) -> None:
        btn = self.console_panel._pause_btn
        btn.setChecked(not btn.isChecked())

    # ------------------------------------------------------------------
    # Persistência
    # ------------------------------------------------------------------
    def _restore_state(self) -> None:
        self.console_panel.load_state(self._settings)
        self.device_panel.load_state(self._settings)
        self.process_panel.load_state(self._settings)
        self.charts_panel.load_state(self._settings)
        self.script_panel.load_state(self._settings)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._settings["window"] = {
            "size": [self.width(), self.height()],
            "pos": [self.x(), self.y()],
        }
        self._settings["theme"] = "dark" if self._dark else "light"
        self.console_panel.save_state(self._settings)
        self.device_panel.save_state(self._settings)
        self.process_panel.save_state(self._settings)
        self.charts_panel.save_state(self._settings)
        self.script_panel.save_state(self._settings)
        save_settings(self._settings)
        super().closeEvent(event)
