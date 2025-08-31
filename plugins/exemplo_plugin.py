"""Plugin de exemplo que adiciona painel de erros e parser colorido.

Autor: Pexe (Instagram: @David.devloli)
"""

import json
import random

from ui.widgets.console_panel import ConsolePanel
from core.models import LogEvent
from parsers import set_key_color, clear_key_colors


class ErrorEventsPanel(ConsolePanel):
    """Painel que exibe apenas logs de nível >= WARNING."""

    def _append_log(self, event: LogEvent) -> None:  # type: ignore[override]
        level = event.level.upper()
        if level.startswith(("W", "E", "C")):
            super()._append_log(event)


def colored_json_parser(text: str):
    """Parser que colore chaves JSON com cores aleatórias."""
    data = json.loads(text)
    clear_key_colors()
    palette = [
        "#ff5555",
        "#55ff55",
        "#5555ff",
        "#ff55ff",
        "#55ffff",
        "#ffff55",
    ]
    for key in data.keys():
        set_key_color(key, random.choice(palette))
    return data


def register(app) -> None:
    panel = ErrorEventsPanel(app.bus)
    app.add_panel("Eventos de Erro", panel)
    app.register_parser("colored_json", colored_json_parser)
