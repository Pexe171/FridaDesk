"""Painel de gráficos.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Deque, Optional

import pyqtgraph as pg
from PyQt6.QtWidgets import (
    QPushButton,
    QVBoxLayout,
    QWidget,
    QMessageBox,
)

from core.event_bus import EventBus
from core.models import MetricSample
from core.collectors import ProcessMetricsCollector
from core.exporters import export_metrics_csv, export_metrics_html


class ChartsPanel(QWidget):
    """Exibe gráficos de CPU% e memória ao longo do tempo."""

    def __init__(self, bus: EventBus) -> None:
        super().__init__()
        self._bus = bus
        self._pid: Optional[int] = None
        self._collector: Optional[ProcessMetricsCollector] = None

        self._times: Deque[float] = deque()
        self._cpu_vals: Deque[float] = deque()
        self._mem_vals: Deque[float] = deque()
        self._samples: Deque[MetricSample] = deque()
        self._max_points = 300

        self._build_ui()
        self._bus.metric_sample.connect(self._on_sample)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        self._start_btn = QPushButton("Iniciar Métricas")
        self._start_btn.setCheckable(True)
        self._start_btn.toggled.connect(self._toggle_collection)
        layout.addWidget(self._start_btn)

        self._export_btn = QPushButton("Exportar Métricas")
        self._export_btn.clicked.connect(self._export)
        layout.addWidget(self._export_btn)

        self._cpu_plot = pg.PlotWidget(title="CPU%")
        self._cpu_plot.setYRange(0, 100)
        self._cpu_curve = self._cpu_plot.plot(pen=pg.mkPen("y"))
        layout.addWidget(self._cpu_plot)

        self._mem_plot = pg.PlotWidget(title="Memória (MB)")
        self._mem_curve = self._mem_plot.plot(pen=pg.mkPen("c"))
        layout.addWidget(self._mem_plot)

    # ------------------------------------------------------------------
    # Estado
    # ------------------------------------------------------------------
    def load_state(self, settings: dict) -> None:
        self._start_btn.setChecked(settings.get("metrics_active", False))

    def save_state(self, settings: dict) -> None:
        settings["metrics_active"] = self._start_btn.isChecked()

    def set_process_pid(self, pid: int) -> None:
        """Define o PID alvo para a coleta."""

        self._pid = pid
        if self._collector:
            asyncio.create_task(self._collector.stop())
            self._collector = None
            self._start_btn.setChecked(False)

    def _toggle_collection(self, checked: bool) -> None:
        if checked and self._pid is not None:
            self._times.clear()
            self._cpu_vals.clear()
            self._mem_vals.clear()
            self._collector = ProcessMetricsCollector(self._pid)
            self._collector.start()
        elif self._collector:
            asyncio.create_task(self._collector.stop())
            self._collector = None

    def _on_sample(self, sample: MetricSample) -> None:
        if sample.process_pid != self._pid:
            return
        self._times.append(sample.ts)
        self._cpu_vals.append(sample.cpu_pct)
        self._mem_vals.append(sample.rss_mb)
        self._samples.append(sample)
        if len(self._times) > self._max_points:
            self._times.popleft()
            self._cpu_vals.popleft()
            self._mem_vals.popleft()
            self._samples.popleft()
        base = self._times[0] if self._times else 0
        x = [t - base for t in self._times]
        self._cpu_curve.setData(x, list(self._cpu_vals))
        self._mem_curve.setData(x, list(self._mem_vals))

    def _export(self) -> None:
        if not self._samples:
            QMessageBox.information(self, "Exportação", "Nenhuma métrica coletada.")
            return
        csv_path = export_metrics_csv(list(self._samples))
        html_path = export_metrics_html(list(self._samples))
        QMessageBox.information(
            self,
            "Exportação",
            f"Métricas salvas em:\n{csv_path}\n{html_path}",
        )

