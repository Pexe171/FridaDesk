"""Modelos de dados utilizando Pydantic.

Autor: Pexe (Instagram: @David.devloli)
"""

from pydantic import BaseModel


class DeviceInfo(BaseModel):
    """Informações básicas de um dispositivo."""

    id: str
    modelo: str
