"""Modelos de dados utilizando Pydantic.

Autor: Pexe (Instagram: @David.devloli)
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class DeviceType(str, Enum):
    """Tipos de dispositivo suportados."""

    LOCAL = "LOCAL"
    USB = "USB"
    EMULATOR = "EMULATOR"


class DeviceInfo(BaseModel):
    """Informações básicas de um dispositivo."""

    id: str
    name: str
    type: DeviceType
    status: Optional[str] = None


class ProcessInfo(BaseModel):
    """Dados sobre um processo em execução."""

    pid: int
    name: str
    user: str


class LogEvent(BaseModel):
    """Evento de log emitido pela aplicação ou por plugins."""

    ts: float
    level: str
    tag: str
    message: str
    raw: str


class MetricSample(BaseModel):
    """Amostra de métricas de desempenho de um processo."""

    ts: float
    cpu_pct: float
    rss_mb: float
    process_pid: int


class NetworkEvent(BaseModel):
    """Resumo de uma requisição capturada pelo proxy."""

    ts: float
    host: str
    method: str
    status: int
    size: int
    request: str
    response: str

