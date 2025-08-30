"""Gerencia uma sessão Frida ativa (attach, detach, script).

Autor: Pexe (Instagram: @David.devloli)
"""

class Session:
    """Encapsula uma sessão de instrumentação com o Frida."""

    def __init__(self) -> None:
        self.script = None

    def attach(self, pid: int) -> None:
        """Anexa-se a um processo identificado por *pid*."""
        raise NotImplementedError

    def detach(self) -> None:
        """Desconecta a sessão atual."""
        raise NotImplementedError
