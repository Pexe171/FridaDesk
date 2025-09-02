"""Integração simples com mitmproxy.

Autor: Pexe (Instagram: @David.devloli)
"""

# mypy: ignore-errors

import asyncio
import time
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    http = Any
    options = Any
    DumpMaster = Any
else:
    from mitmproxy import http, options  # type: ignore
    from mitmproxy.tools.dump import DumpMaster  # type: ignore

from .event_bus import publish
from .models import NetworkEvent


class _FlowCollector:
    """Addon que publica eventos de rede no bus."""

    def __init__(self) -> None:
        self.bus = None

    def configure(self, bus) -> None:
        self.bus = bus

    def response(self, flow: http.HTTPFlow) -> None:  # pragma: no cover - depende de mitmproxy
        if not self.bus:
            return
        event = NetworkEvent(
            ts=time.time(),
            host=flow.request.host,
            method=flow.request.method,
            status=flow.response.status_code if flow.response else 0,
            size=len(flow.response.content or b""),
            request=flow.request.text or "",
            response=flow.response.text if flow.response else "",
        )
        publish(event)


async def _run(master: DumpMaster) -> None:
    await master.run()


def start_proxy(bus, host: str = "127.0.0.1", port: int = 8080) -> DumpMaster:
    """Inicia o proxy de rede."""
    opts = options.Options(listen_host=host, listen_port=port)
    m = DumpMaster(opts, with_termlog=False, with_dumper=False)
    collector = _FlowCollector()
    collector.configure(bus)
    m.addons.add(collector)
    asyncio.create_task(_run(m))
    return m


def stop_proxy(master: Optional[DumpMaster]) -> None:
    """Encerra o proxy de rede."""
    if master:
        master.shutdown()
