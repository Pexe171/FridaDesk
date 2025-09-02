"""Temas visuais da interface.

Autor: Pexe (Instagram: @David.devloli)
"""

PALETTE = {
    "background": "#1a1b26",
    "primary": "#00ffff",
    "secondary": "#39ff14",
    "error": "#ff4500",
    "text": "#e0e0e0",
    "text_secondary": "#a0a0a0",
}

DARK_CYBERPUNK_QSS = f"""
QWidget {{
    background-color: {PALETTE['background']};
    color: {PALETTE['text']};
}}
QLabel {{
    color: {PALETTE['text_secondary']};
}}
QPushButton {{
    background-color: {PALETTE['background']};
    color: {PALETTE['text']};
    border: 1px solid {PALETTE['primary']};
    padding: 4px;
}}
QPushButton:hover {{
    background-color: {PALETTE['primary']};
    color: {PALETTE['background']};
}}
QPushButton:pressed {{
    background-color: #00cccc;
}}
QTabWidget::pane {{
    border: 1px solid {PALETTE['primary']};
}}
QTabBar::tab {{
    background: {PALETTE['background']};
    border: 1px solid {PALETTE['primary']};
    padding: 4px;
}}
QTabBar::tab:selected {{
    background: {PALETTE['primary']};
    color: {PALETTE['background']};
}}
QLineEdit, QTextEdit {{
    background-color: #242638;
    color: {PALETTE['text']};
    border: 1px solid {PALETTE['primary']};
}}
QTreeView, QListView {{
    background-color: #242638;
    color: {PALETTE['text']};
    border: 1px solid {PALETTE['primary']};
}}
QProgressBar {{
    border: 1px solid {PALETTE['primary']};
    text-align: center;
}}
QProgressBar::chunk {{
    background-color: {PALETTE['secondary']};
}}
QStatusBar {{
    background-color: {PALETTE['background']};
    color: {PALETTE['text_secondary']};
}}
QWidget:focus {{
    border: 1px solid {PALETTE['primary']};
}}
"""

def dark_cyberpunk() -> str:
    """Retorna o tema dark cyberpunk profissional."""
    return DARK_CYBERPUNK_QSS
