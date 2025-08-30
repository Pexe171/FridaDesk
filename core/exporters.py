"""Módulo para exportação de dados.

Autor: Pexe (Instagram: @David.devloli)
"""


class BaseExporter:
    """Classe base para exportadores."""

    def export(self) -> None:
        """Realiza a exportação dos dados."""
        raise NotImplementedError
