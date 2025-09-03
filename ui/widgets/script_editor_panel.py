"""Painel de edição e injeção de scripts.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QComboBox,
    QPlainTextEdit,
    QLineEdit,
    QVBoxLayout,
    QWidget,
    QInputDialog,
)

from core.frida_manager import FridaManager
from core.models import ProcessInfo
from core.event_bus import get_event_bus
from core.codeshare import baixar_script


class JavaScriptHighlighter(QSyntaxHighlighter):
    """Realce simples de sintaxe para JavaScript."""

    def __init__(self, document) -> None:
        super().__init__(document)
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(Qt.GlobalColor.blue)
        keywords = [
            "break",
            "case",
            "catch",
            "class",
            "const",
            "continue",
            "debugger",
            "default",
            "delete",
            "do",
            "else",
            "export",
            "extends",
            "finally",
            "for",
            "function",
            "if",
            "import",
            "in",
            "instanceof",
            "let",
            "new",
            "return",
            "super",
            "switch",
            "this",
            "throw",
            "try",
            "typeof",
            "var",
            "void",
            "while",
            "with",
            "yield",
        ]
        self.rules: List[tuple[re.Pattern[str], QTextCharFormat]] = [
            (re.compile(r"\b" + kw + r"\b"), keyword_format) for kw in keywords
        ]

        string_format = QTextCharFormat()
        string_format.setForeground(Qt.GlobalColor.darkGreen)
        self.rules.append((re.compile(r"'[^'\n]*'"), string_format))
        self.rules.append((re.compile(r'"[^"\n]*"'), string_format))

        comment_format = QTextCharFormat()
        comment_format.setForeground(Qt.GlobalColor.gray)
        self.rules.append((re.compile(r"//[^\n]*"), comment_format))

    def highlightBlock(self, text: str) -> None:  # type: ignore[override]
        for pattern, fmt in self.rules:
            for match in pattern.finditer(text):
                start, end = match.span()
                self.setFormat(start, end - start, fmt)


class ScriptEditorPanel(QWidget):
    """Editor de scripts com opções de carregamento e injeção."""

    def __init__(self, manager: FridaManager) -> None:
        super().__init__()
        self._manager = manager
        self._process_panel = None
        self._bus = get_event_bus()
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        controls = QHBoxLayout()

        self._process_combo = QComboBox()
        controls.addWidget(self._process_combo)

        load_btn = QPushButton("Carregar Script")
        load_btn.clicked.connect(self._load_script)
        controls.addWidget(load_btn)

        codeshare_btn = QPushButton("CodeShare")
        codeshare_btn.clicked.connect(self._load_codeshare)
        controls.addWidget(codeshare_btn)

        save_btn = QPushButton("Salvar Script")
        save_btn.clicked.connect(self._save_script)
        controls.addWidget(save_btn)

        inject_btn = QPushButton("Injetar Script")
        inject_btn.clicked.connect(self._inject_script)
        controls.addWidget(inject_btn)

        layout.addLayout(controls)

        self._editor = QPlainTextEdit()
        layout.addWidget(self._editor)
        self._highlighter = JavaScriptHighlighter(self._editor.document())

        msg_layout = QHBoxLayout()
        self._message_input = QLineEdit()
        self._message_input.setPlaceholderText("Mensagem para o script")
        send_btn = QPushButton("Enviar Mensagem")
        send_btn.clicked.connect(self._send_message)
        msg_layout.addWidget(self._message_input)
        msg_layout.addWidget(send_btn)
        layout.addLayout(msg_layout)

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
    def _load_script(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Carregar Script",
            "",
            "Arquivos JavaScript (*.js);;Todos os arquivos (*)",
        )
        if not path:
            return
        try:
            code = Path(path).read_text(encoding="utf-8")
            self._editor.setPlainText(code)
        except Exception as exc:  # pragma: no cover - erros de IO
            QMessageBox.critical(self, "Erro", str(exc))

    def _load_codeshare(self) -> None:
        texto, ok = QInputDialog.getText(
            self, "CodeShare", "Link ou comando:")
        if not ok or not texto.strip():
            return
        try:
            code = baixar_script(texto)
            self._editor.setPlainText(code)
        except Exception as exc:  # pragma: no cover - falhas de rede
            QMessageBox.critical(self, "Erro", str(exc))

    def _save_script(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Salvar Script",
            "",
            "Arquivos JavaScript (*.js);;Todos os arquivos (*)",
        )
        if not path:
            return
        try:
            Path(path).write_text(self._editor.toPlainText(), encoding="utf-8")
        except Exception as exc:  # pragma: no cover - erros de IO
            QMessageBox.critical(self, "Erro", str(exc))

    def _inject_script(self) -> None:
        target_text = self._process_combo.currentText()
        if not target_text:
            QMessageBox.warning(self, "Injeção", "Selecione um processo")
            return
        if "(" in target_text and target_text.endswith(")"):
            pid_part = target_text.split("(")[-1].rstrip(")")
            target = int(pid_part) if pid_part.isdigit() else target_text
        else:
            target = target_text
        code = self._editor.toPlainText()
        if not code.strip():
            QMessageBox.warning(self, "Injeção", "O script está vazio")
            return
        try:
            self._manager.attach(target)
            self._manager.inject_script_from_text(code)
            self._status("Script injetado")
        except Exception as exc:  # pragma: no cover - falhas da frida
            QMessageBox.critical(self, "Erro", str(exc))

    def _send_message(self) -> None:
        text = self._message_input.text()
        if not text.strip():
            return
        self._bus.frida_send_to_script.emit(text)
        self._message_input.clear()
        self._status("Mensagem enviada")

    def _status(self, text: str) -> None:
        win = self.window()
        if hasattr(win, "statusBar"):
            win.statusBar().showMessage(text, 3000)
