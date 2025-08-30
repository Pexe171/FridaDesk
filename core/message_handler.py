"""Processa mensagens de/para os scripts.

Autor: Pexe (Instagram: @David.devloli)
"""

class MessageHandler:
    """Recebe e envia mensagens entre a aplicação e os scripts Frida."""

    def tratar_mensagem(self, mensagem: dict) -> None:
        """Processa uma única mensagem proveniente do script."""
        raise NotImplementedError
