"""Painel para edição e injeção de scripts Frida.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import QRegularExpression
from PyQt6.QtGui import QColor, QSyntaxHighlighter, QTextCharFormat
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QComboBox,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.frida_manager import FridaManager
from core.models import ProcessInfo

if TYPE_CHECKING:  # pragma: no cover
    from .process_panel import ProcessPanel


class _JSHighlighter(QSyntaxHighlighter):
    """Realce simples de sintaxe para JavaScript."""

    def __init__(self, document) -> None:  # type: ignore[override]
        super().__init__(document)
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("blue"))
        keywords = [
            "function",
            "var",
            "let",
            "const",
            "if",
            "else",
            "for",
            "while",
            "return",
            "new",
            "class",
            "this",
        ]
        self._rules: list[tuple[QRegularExpression, QTextCharFormat]] = [
            (QRegularExpression(fr"\\b{kw}\\b"), keyword_format) for kw in keywords
        ]

        string_format = QTextCharFormat()
        string_format.setForeground(QColor("darkgreen"))
        self._rules.append((QRegularExpression(r'"[^"\\]*(\\.[^"\\]*)*"'), string_format))
        self._rules.append((QRegularExpression(r"'[^'\\]*(\\.[^'\\]*)*'"), string_format))

        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("darkGray"))
        self._comment_format = comment_format
        self._rules.append((QRegularExpression(r"//[^\n]*"), comment_format))
        self._multiline_start = QRegularExpression(r"/\\*")
        self._multiline_end = QRegularExpression(r"\\*/")

    def highlightBlock(self, text: str) -> None:  # type: ignore[override]
        for pattern, fmt in self._rules:
            it = pattern.globalMatch(text)
            while it.hasNext():
                match = it.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), fmt)

        self.setCurrentBlockState(0)
        start = 0
        if self.previousBlockState() != 1:
            start = text.find("/*")
        else:
            start = 0
        while start >= 0:
            end = text.find("*/", start)
            if end == -1:
                self.setCurrentBlockState(1)
                length = len(text) - start
            else:
                length = end - start + 2
            self.setFormat(start, length, self._comment_format)
            if end == -1:
                break
            start = text.find("/*", end + 2)


class ScriptEditorPanel(QWidget):
    """Permite escrever, carregar e injetar scripts Frida."""

    def __init__(self, manager: FridaManager) -> None:
        super().__init__()
        self._manager = manager
        self._process_panel: ProcessPanel | None = None
        self._last_path = ""

        layout = QVBoxLayout(self)

        self._proc_combo = QComboBox()
        layout.addWidget(self._proc_combo)

        self._editor = QPlainTextEdit()
        self._editor.setPlaceholderText("Escreva o script aqui...")
        _JSHighlighter(self._editor.document())
        layout.addWidget(self._editor)

        btn_layout = QHBoxLayout()
        load_btn = QPushButton("Carregar Script")
        load_btn.clicked.connect(self._load_script)
        btn_layout.addWidget(load_btn)

        save_btn = QPushButton("Salvar Script")
        save_btn.clicked.connect(self._save_script)
        btn_layout.addWidget(save_btn)

        inject_btn = QPushButton("Injetar Script")
        inject_btn.clicked.connect(self._inject_script)
        btn_layout.addWidget(inject_btn)

        layout.addLayout(btn_layout)

        self._proc_combo.currentTextChanged.connect(self._combo_changed)

    # ------------------------------------------------------------------
    # Integração com ProcessPanel
    # ------------------------------------------------------------------
    def set_process_panel(self, panel: "ProcessPanel") -> None:
        self._process_panel = panel
        panel._manager.processes_ready.connect(self._update_processes)
        panel._list.currentTextChanged.connect(self._sync_from_panel)
        self._refresh_from_panel()

    def _refresh_from_panel(self) -> None:
        if not self._process_panel:
            return
        processes: list[ProcessInfo] = []
        for i in range(self._process_panel._list.count()):
            text = self._process_panel._list.item(i).text()
            if "(" in text and text.endswith(")"):
                try:
                    pid = int(text.split("(")[-1].rstrip(")"))
                except ValueError:
                    pid = 0
                name = text[: text.rfind("(")].strip()
            else:
                name = text
                pid = 0
            processes.append(ProcessInfo(pid=pid, name=name, user=""))
        self._update_processes(processes)

    def _update_processes(self, processes: list[ProcessInfo]) -> None:
        self._proc_combo.blockSignals(True)
        self._proc_combo.clear()
        for proc in processes:
            self._proc_combo.addItem(f"{proc.name} ({proc.pid})")
        self._proc_combo.blockSignals(False)

    def _sync_from_panel(self, text: str) -> None:
        idx = self._proc_combo.findText(text)
        if idx >= 0:
            self._proc_combo.setCurrentIndex(idx)

    def _combo_changed(self, text: str) -> None:
        if self._process_panel:
            self._process_panel.set_current_process(text)

    # ------------------------------------------------------------------
    # Persistência
    # ------------------------------------------------------------------
    def load_state(self, settings: dict) -> None:
        path = settings.get("last_script", "")
        if path and Path(path).is_file():
            self._editor.setPlainText(Path(path).read_text(encoding="utf-8"))
            self._last_path = path
        proc = settings.get("last_script_process", "")
        idx = self._proc_combo.findText(proc)
        if idx >= 0:
            self._proc_combo.setCurrentIndex(idx)

    def save_state(self, settings: dict) -> None:
        settings["last_script"] = self._last_path
        settings["last_script_process"] = self._proc_combo.currentText()

    # ------------------------------------------------------------------
    # Ações de UI
    # ------------------------------------------------------------------
    def _load_script(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Carregar Script", "", "Arquivos JS (*.js);;Todos (*.*)")
        if path:
            try:
                self._editor.setPlainText(Path(path).read_text(encoding="utf-8"))
                self._last_path = path
            except Exception as exc:  # pragma: no cover - erros inesperados
                QMessageBox.critical(self, "Erro", f"Falha ao carregar script:\n{exc}")

    def _save_script(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Salvar Script", "", "Arquivos JS (*.js);;Todos (*.*)")
        if path:
            try:
                Path(path).write_text(self._editor.toPlainText(), encoding="utf-8")
                self._last_path = path
            except Exception as exc:  # pragma: no cover - erros inesperados
                QMessageBox.critical(self, "Erro", f"Falha ao salvar script:\n{exc}")

    def _inject_script(self) -> None:
        target_text = self._proc_combo.currentText()
        if not target_text:
            QMessageBox.warning(self, "Injeção", "Selecione um processo." )
            return
        target: int | str
        if "(" in target_text and target_text.endswith(")"):
            try:
                target = int(target_text.split("(")[-1].rstrip(")"))
            except ValueError:
                target = target_text
        else:
            target = target_text
        try:
            self._manager.detach()
            self._manager.attach(target)
            self._manager.inject_script_from_text(self._editor.toPlainText())
            QMessageBox.information(self, "Injeção", "Script injetado com sucesso.")
        except Exception as exc:  # pragma: no cover - depende do ambiente
            QMessageBox.critical(self, "Injeção", f"Falha ao injetar script:\n{exc}")
