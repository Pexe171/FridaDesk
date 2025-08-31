"""Painel de gráficos.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import asyncio
from typing import List, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QLabel,
    QVBoxLayout,
    QWidget,
    QPushButton,
)

try:  # pragma: no cover - dependência opcional
    import pyqtgraph as pg
except Exception:  # pragma: no cover
    pg = None

from core.collectors import ProcessMetricsCollector
from core.event_bus import EventBus
from core.models import MetricSample


class ChartsPanel(QWidget):
    """Exibe gráficos de CPU e memória do processo selecionado."""

    def __init__(self, bus: EventBus) -> None:
        super().__init__()
        self._bus = bus
        self._pid: Optional[int] = None
        self._collector: Optional[ProcessMetricsCollector] = None
        self._cpu_data: List[float] = []
        self._mem_data: List[float] = []
        self._max_samples = 300

        layout = QVBoxLayout(self)

        self._start_btn = QPushButton("Iniciar Métricas")
        self._start_btn.clicked.connect(self._toggle_metrics)
        layout.addWidget(self._start_btn)

        if pg is None:
            placeholder = QLabel("pyqtgraph não disponível")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(placeholder)
        else:
            self._cpu_plot = pg.PlotWidget(title="CPU %")
            self._cpu_curve = self._cpu_plot.plot(pen="y")
            self._mem_plot = pg.PlotWidget(title="Memória (MB)")
            self._mem_curve = self._mem_plot.plot(pen="c")
            layout.addWidget(self._cpu_plot)
            layout.addWidget(self._mem_plot)
            self._bus.metric_sample.connect(self._update_charts)

    def set_process(self, pid: int) -> None:
        """Define o PID do processo alvo."""

        self._pid = pid

    def _toggle_metrics(self) -> None:
        if self._collector:
            asyncio.create_task(self._collector.stop())
            self._collector = None
            self._start_btn.setText("Iniciar Métricas")
            return
        if self._pid is None:
            return
        self._collector = ProcessMetricsCollector(self._pid)
        self._collector.start()
        self._start_btn.setText("Parar Métricas")

    def _update_charts(self, sample: MetricSample) -> None:
        if pg is None or sample.process_pid != self._pid:
            return
        self._cpu_data.append(sample.cpu_pct)
        self._mem_data.append(sample.rss_mb)
        self._cpu_data = self._cpu_data[-self._max_samples :]
        self._mem_data = self._mem_data[-self._max_samples :]
        self._cpu_curve.setData(self._cpu_data)
        self._mem_curve.setData(self._mem_data)
