"""Painel de edição e injeção de scripts.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from PyQt6.QtCore import Qt, QRect, QSize
from PyQt6.QtGui import (
    QSyntaxHighlighter,
    QTextCharFormat,
    QFontDatabase,
    QFont,
    QPainter,
    QColor,
    QTextFormat,
)
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QComboBox,
    QLineEdit,
    QVBoxLayout,
    QWidget,
    QPlainTextEdit,
    QTextEdit,
    QStyle,
)

from core.frida_manager import FridaManager
from core.models import ProcessInfo
from core.event_bus import get_event_bus


class LineNumberArea(QWidget):
    def __init__(self, editor: "CodeEditor") -> None:
        super().__init__(editor)
        self._editor = editor

    def sizeHint(self):  # type: ignore[override]
        return QSize(self._editor.line_number_area_width(), 0)

    def paintEvent(self, event):  # type: ignore[override]
        self._editor.line_number_area_paint_event(event)


class CodeEditor(QPlainTextEdit):
    def __init__(self) -> None:
        super().__init__()
        self._line_number_area = LineNumberArea(self)
        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        self.cursorPositionChanged.connect(self.highlight_current_line)
        self.update_line_number_area_width(0)
        self.highlight_current_line()

    def line_number_area_width(self) -> int:
        digits = len(str(max(1, self.blockCount())))
        return 3 + self.fontMetrics().horizontalAdvance("9") * digits

    def update_line_number_area_width(self, _):
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def update_line_number_area(self, rect, dy):
        if dy:
            self._line_number_area.scroll(0, dy)
        else:
            self._line_number_area.update(0, rect.y(), self._line_number_area.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self.update_line_number_area_width(0)

    def resizeEvent(self, event):  # type: ignore[override]
        super().resizeEvent(event)
        cr = self.contentsRect()
        self._line_number_area.setGeometry(QRect(cr.left(), cr.top(), self.line_number_area_width(), cr.height()))

    def line_number_area_paint_event(self, event):
        painter = QPainter(self._line_number_area)
        painter.fillRect(event.rect(), QColor("#1e1e1e"))

        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = int(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + int(self.blockBoundingRect(block).height())

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                painter.setPen(QColor("#00ffff"))
                painter.drawText(0, top, self._line_number_area.width() - 2, self.fontMetrics().height(), Qt.AlignmentFlag.AlignRight, number)
            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            block_number += 1

    def highlight_current_line(self) -> None:
        extra = []
        if not self.isReadOnly():
            selection = QTextEdit.ExtraSelection()
            line_color = QColor("#00ffff20")
            selection.format.setBackground(line_color)
            if hasattr(QTextFormat, "FullWidthSelection"):
                prop = QTextFormat.FullWidthSelection
            else:  # PyQt6
                prop = QTextFormat.Property.FullWidthSelection
            selection.format.setProperty(prop, True)
            selection.cursor = self.textCursor()
            selection.cursor.clearSelection()
            extra.append(selection)
        self.setExtraSelections(extra)


class JavaScriptHighlighter(QSyntaxHighlighter):
    """Realce simples de sintaxe para JavaScript com cores vibrantes."""

    def __init__(self, document) -> None:
        super().__init__(document)
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#ff7edb"))
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
        string_format.setForeground(QColor("#fede5d"))
        self.rules.append((re.compile(r"'[^'\n]*'"), string_format))
        self.rules.append((re.compile(r'"[^"\n]*"'), string_format))

        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#00ffff"))
        self.rules.append((re.compile(r"\b\d+\b"), number_format))

        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#5f7187"))
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

        style = self.style()

        inject_btn = QPushButton("Injetar")
        inject_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
        inject_btn.clicked.connect(self._inject_script)
        inject_btn.setStyleSheet("color: #00ffff;")
        controls.addWidget(inject_btn)

        load_btn = QPushButton("Carregar")
        load_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_DialogOpenButton))
        load_btn.clicked.connect(self._load_script)
        load_btn.setStyleSheet("color: #00ffff;")
        controls.addWidget(load_btn)

        save_btn = QPushButton("Salvar")
        save_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton))
        save_btn.clicked.connect(self._save_script)
        save_btn.setStyleSheet("color: #00ffff;")
        controls.addWidget(save_btn)

        layout.addLayout(controls)

        self._editor = CodeEditor()
        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setFamilies(["monospace"])
        self._editor.setFont(mono)
        self._editor.setStyleSheet(
            """
            QPlainTextEdit {
                background-color: #2b213a;
                color: #f8f8f2;
                selection-background-color: #00ffff33;
            }
            """
        )
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
            self._process_combo.addItem(f"{proc.name} (PID: {proc.pid})")
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
