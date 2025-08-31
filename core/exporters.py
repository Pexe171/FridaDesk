"""Módulo para exportação de dados.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import base64
import csv
import json
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Iterable

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from jinja2 import Environment

from .models import LogEvent, MetricSample

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)


def _timestamp() -> str:
    """Retorna timestamp para nome de arquivo."""

    return datetime.now().strftime("%Y%m%d_%H%M%S")


def export_logs_json(logs: Iterable[LogEvent]) -> Path:
    """Exporta logs em formato JSON."""

    path = LOG_DIR / f"logs_{_timestamp()}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([log.model_dump() for log in logs], fh, ensure_ascii=False, indent=2)
    return path


def export_logs_csv(logs: Iterable[LogEvent]) -> Path:
    """Exporta logs em formato CSV."""

    path = LOG_DIR / f"logs_{_timestamp()}.csv"
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ts", "level", "tag", "message"])
        for log in logs:
            writer.writerow([log.ts, log.level, log.tag, log.message])
    return path


def export_metrics_csv(samples: Iterable[MetricSample]) -> Path:
    """Exporta série de métricas em CSV."""

    path = LOG_DIR / f"metrics_{_timestamp()}.csv"
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ts", "cpu_pct", "rss_mb", "process_pid"])
        for s in samples:
            writer.writerow([s.ts, s.cpu_pct, s.rss_mb, s.process_pid])
    return path


def export_metrics_html(samples: Iterable[MetricSample]) -> Path:
    """Gera relatório HTML com gráficos em base64."""

    samples = list(samples)
    if not samples:
        raise ValueError("Nenhuma amostra disponível")

    ts = [s.ts for s in samples]
    cpu = [s.cpu_pct for s in samples]
    mem = [s.rss_mb for s in samples]

    def _plot_to_b64(x, y, title, ylabel) -> str:
        fig, ax = plt.subplots()
        ax.plot(x, y)
        ax.set_title(title)
        ax.set_xlabel("Tempo")
        ax.set_ylabel(ylabel)
        buf = BytesIO()
        fig.savefig(buf, format="png")
        plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode("utf-8")

    cpu_b64 = _plot_to_b64(ts, cpu, "CPU (%)", "CPU%")
    mem_b64 = _plot_to_b64(ts, mem, "Memória (MB)", "MB")

    template = """
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"><title>Relatório de Métricas</title></head>
    <body>
        <h1>Relatório de Métricas</h1>
        <h2>CPU (%)</h2>
        <img src="data:image/png;base64,{{ cpu_chart }}" />
        <h2>Memória (MB)</h2>
        <img src="data:image/png;base64,{{ mem_chart }}" />
    </body>
    </html>
    """

    html = Environment().from_string(template).render(
        cpu_chart=cpu_b64, mem_chart=mem_b64
    )

    path = LOG_DIR / f"metrics_{_timestamp()}.html"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path


__all__ = [
    "export_logs_json",
    "export_logs_csv",
    "export_metrics_csv",
    "export_metrics_html",
]

