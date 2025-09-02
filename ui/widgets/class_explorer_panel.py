"""Explorador de classes e métodos.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

from typing import List

from PyQt6.QtWidgets import (
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QComboBox,
    QHBoxLayout,
    QVBoxLayout,
    QWidget,
)

from core.frida_manager import FridaManager
from core.models import ProcessInfo
from core.event_bus import get_event_bus


class ClassExplorerPanel(QWidget):
    """Lista classes e métodos do processo selecionado."""

    def __init__(self, manager: FridaManager) -> None:
        super().__init__()
        self._manager = manager
        self._process_panel = None
        self._bus = get_event_bus()
        self._bus.frida_message_received.connect(self._on_message)
        self._awaiting = ""
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        self._process_combo = QComboBox()
        controls.addWidget(self._process_combo)
        enum_btn = QPushButton("Enumerar Classes")
        enum_btn.clicked.connect(self._enumerate_classes)
        controls.addWidget(enum_btn)
        layout.addLayout(controls)

        lists = QHBoxLayout()
        self._classes = QListWidget()
        self._classes.currentTextChanged.connect(self._enumerate_methods)
        lists.addWidget(self._classes)
        self._methods = QListWidget()
        lists.addWidget(self._methods)
        layout.addLayout(lists)

    # ------------------------------------------------------------------
    # Integração com ProcessPanel
    # ------------------------------------------------------------------
    def set_process_panel(self, panel) -> None:
        self._process_panel = panel
        panel._manager.processes_ready.connect(self._update_processes)
        panel._list.currentTextChanged.connect(self._sync_current)
        self._copy_existing()

    def _copy_existing(self) -> None:
        if not self._process_panel:
            return
        items = [
            self._process_panel._list.item(i).text()
            for i in range(self._process_panel._list.count())
        ]
        self._process_combo.clear()
        self._process_combo.addItems(items)
        self._sync_current(self._process_panel.current_process())

    def _update_processes(self, processes: List[ProcessInfo]) -> None:
        self._process_combo.clear()
        for proc in processes:
            self._process_combo.addItem(f"{proc.name} ({proc.pid})")
        if self._process_panel:
            self._sync_current(self._process_panel.current_process())

    def _sync_current(self, text: str) -> None:
        idx = self._process_combo.findText(text)
        if idx >= 0:
            self._process_combo.setCurrentIndex(idx)

    # ------------------------------------------------------------------
    # Ações
    # ------------------------------------------------------------------
    def _target_from_combo(self):
        target_text = self._process_combo.currentText()
        if not target_text:
            return None
        if "(" in target_text and target_text.endswith(")"):
            pid_part = target_text.split("(")[-1].rstrip(")")
            return int(pid_part) if pid_part.isdigit() else target_text
        return target_text

    def _enumerate_classes(self) -> None:
        target = self._target_from_combo()
        if target is None:
            QMessageBox.warning(self, "Classes", "Selecione um processo")
            return
        self._classes.clear()
        self._methods.clear()
        script = (
            "Java.perform(function(){" +
            "var classes = Java.enumerateLoadedClassesSync();" +
            "send({type:'classes', data: classes});" +
            "});"
        )
        try:
            self._awaiting = "classes"
            self._manager.attach(target)
            self._manager.inject_script_from_text(script)
        except Exception as exc:
            QMessageBox.critical(self, "Erro", str(exc))

    def _enumerate_methods(self, class_name: str) -> None:
        if not class_name:
            return
        target = self._target_from_combo()
        if target is None:
            return
        self._methods.clear()
        script = (
            "Java.perform(function(){" +
            f"var cls = Java.use('{class_name}');" +
            "var methods = cls.class.getDeclaredMethods().map(function(m){return m.toString();});" +
            "send({type:'methods', data: methods});" +
            "});"
        )
        try:
            self._awaiting = "methods"
            self._manager.attach(target)
            self._manager.inject_script_from_text(script)
        except Exception as exc:
            QMessageBox.critical(self, "Erro", str(exc))

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------
    def _on_message(self, payload: object) -> None:
        if not isinstance(payload, dict):
            return
        if self._awaiting == "classes" and payload.get("type") == "classes":
            for name in payload.get("data", []):
                self._classes.addItem(QListWidgetItem(name))
            self._manager.detach()
            self._awaiting = ""
        elif self._awaiting == "methods" and payload.get("type") == "methods":
            for m in payload.get("data", []):
                self._methods.addItem(QListWidgetItem(m))
            self._manager.detach()
            self._awaiting = ""
