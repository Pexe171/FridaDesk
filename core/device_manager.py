"""Lógica para listar e conectar a dispositivos/processos.

Autor: Pexe (Instagram: @David.devloli)
"""

class DeviceManager:
    """Responsável por interagir com dispositivos e processos."""

    def listar_dispositivos(self) -> list:
        """Retorna uma lista de dispositivos disponíveis."""
        raise NotImplementedError
