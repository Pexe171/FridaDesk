"""Módulo para coletores de dados.

Autor: Pexe (Instagram: @David.devloli)
"""


class BaseCollector:
    """Classe base para coletores."""

    def collect(self) -> None:
        """Executa a coleta de dados."""
        raise NotImplementedError
