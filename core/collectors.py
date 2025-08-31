"""Módulo para coletores de dados.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime
from typing import Iterable, Optional

from .event_bus import publish
from .models import LogEvent, MetricSample


class BaseCollector:
    """Classe base para coletores."""

    def collect(self) -> None:  # pragma: no cover - interface
        """Executa a coleta de dados."""
        raise NotImplementedError


class LogcatCollector(BaseCollector):
    """Coletor assíncrono de logs via ``adb logcat``."""

    LOG_RE = re.compile(
        r"^(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+"
        r"(?P<level>[VDIWE])/(?P<tag>[^:]+): (?P<msg>.*)$"
    )

    def __init__(
        self,
        level: Optional[Iterable[str]] = None,
        tag: Optional[str] = None,
        pattern: Optional[str] = None,
    ) -> None:
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._task: Optional[asyncio.Task[None]] = None
        self._running = False

        self.level_filter = set(level) if level else None
        self.tag_filter = tag
        self.regex = re.compile(pattern) if pattern else None

    def start(self) -> None:
        """Inicia a coleta em segundo plano."""

        if not self._task:
            self._running = True
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Interrompe a coleta."""

        self._running = False
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            await self._proc.wait()
        if self._task:
            await self._task
        self._task = None
        self._proc = None

    async def _run(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            "adb",
            "logcat",
            "-v",
            "time",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        assert self._proc.stdout is not None
        while self._running:
            line = await self._proc.stdout.readline()
            if not line:
                break
            text = line.decode(errors="replace").strip()
            event = self._parse_line(text)
            if event and self._matches(event):
                publish(event)

    def _parse_line(self, line: str) -> Optional[LogEvent]:
        match = self.LOG_RE.match(line)
        if not match:
            return None
        ts_str = match.group("ts")
        try:
            dt = datetime.strptime(ts_str, "%m-%d %H:%M:%S.%f")
            dt = dt.replace(year=datetime.now().year)
            ts = dt.timestamp()
        except Exception:
            ts = datetime.now().timestamp()
        return LogEvent(
            ts=ts,
            level=match.group("level"),
            tag=match.group("tag"),
            message=match.group("msg"),
            raw=line,
        )

    def _matches(self, event: LogEvent) -> bool:
        if self.level_filter and event.level not in self.level_filter:
            return False
        if self.tag_filter and self.tag_filter != event.tag:
            return False
        if self.regex and not self.regex.search(event.message):
            return False
        return True

    def update_filters(
        self,
        level: Optional[Iterable[str]] = None,
        tag: Optional[str] = None,
        pattern: Optional[str] = None,
    ) -> None:
        """Atualiza filtros aplicados ao stream."""

        if level is not None:
            self.level_filter = set(level)
        if tag is not None:
            self.tag_filter = tag
        if pattern is not None:
            self.regex = re.compile(pattern) if pattern else None


class ProcessMetricsCollector(BaseCollector):
    """Coletor periódico de métricas de CPU e memória de um processo."""

    def __init__(self, pid: int, interval: float = 1.0) -> None:
        self.pid = pid
        self.interval = interval
        self._task: Optional[asyncio.Task[None]] = None
        self._running = False

    def start(self) -> None:
        """Inicia a coleta em segundo plano."""

        if not self._task:
            self._running = True
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Interrompe a coleta."""

        self._running = False
        if self._task:
            await self._task
        self._task = None

    async def _run(self) -> None:
        while self._running:
            cpu, rss = await self._sample()
            publish(
                MetricSample(
                    ts=datetime.now().timestamp(),
                    cpu_pct=cpu,
                    rss_mb=rss,
                    process_pid=self.pid,
                )
            )
            await asyncio.sleep(self.interval)

    async def _sample(self) -> tuple[float, float]:
        proc = await asyncio.create_subprocess_exec(
            "adb",
            "shell",
            "top",
            "-n",
            "1",
            "-b",
            "-p",
            str(self.pid),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await proc.communicate()
        cpu = 0.0
        rss = 0.0
        if out:
            text = out.decode(errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if not line.startswith(str(self.pid)):
                    continue
                parts = line.split()
                try:
                    # saída do top: PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ ARGS
                    cpu = float(parts[8])
                    rss = self._parse_mem(parts[5])
                except Exception:
                    pass
                break
        return cpu, rss

    @staticmethod
    def _parse_mem(value: str) -> float:
        """Converte valores do ``top`` em MB."""

        try:
            if value.lower().endswith("m"):
                return float(value[:-1])
            if value.lower().endswith("k"):
                return float(value[:-1]) / 1024
            return float(value) / (1024 * 1024)
        except Exception:
            return 0.0
