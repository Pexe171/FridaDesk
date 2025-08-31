"""Carregador de plugins.

Autor: Pexe (Instagram: @David.devloli)
"""

import importlib.util
from pathlib import Path
from typing import Callable

from parsers import register_parser


class PluginApp:
    """API mínima exposta aos plugins."""

    def __init__(self, window, bus) -> None:
        self.window = window
        self.bus = bus

    def add_panel(self, name: str, widget) -> None:
        self.window.data_tabs.addTab(widget, name)

    def register_parser(self, name: str, func: Callable[[str], object]) -> None:
        register_parser(name, func)

    def add_menu_action(self, title: str, callback) -> None:
        self.window.add_plugin_menu_action(title, callback)


def load_plugins(window, bus, plugins_dir: Path | None = None) -> None:
    """Carrega módulos Python de ``plugins/`` e executa ``register``."""
    plugins_dir = plugins_dir or Path(__file__).resolve().parent.parent / "plugins"
    app = PluginApp(window, bus)
    for path in plugins_dir.glob("*.py"):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if not spec or not spec.loader:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[arg-type]
        if hasattr(module, "register"):
            module.register(app)
