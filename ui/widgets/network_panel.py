"""Painel de tráfego de rede.

Autor: Pexe (Instagram: @David.devloli)
"""

from typing import List

from PyQt6.QtWidgets import (
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.event_bus import EventBus
from core.models import NetworkEvent
from core.exporters import export_network_json, export_network_har
from core.network_proxy import start_proxy, stop_proxy


class NetworkPanel(QWidget):
    """Exibe requisições capturadas pelo proxy."""

    def __init__(self, bus: EventBus) -> None:
        super().__init__()
        self._bus = bus
        self._events: List[NetworkEvent] = []
        self._proxy = None
        self._build_ui()
        bus.network_event.connect(self._append)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        self._proxy_btn = QPushButton("Ativar Proxy")
        self._proxy_btn.setCheckable(True)
        self._proxy_btn.toggled.connect(self._toggle_proxy)
        controls.addWidget(self._proxy_btn)
        export_btn = QPushButton("Exportar")
        export_btn.clicked.connect(self._export)
        controls.addWidget(export_btn)
        layout.addLayout(controls)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Host", "Método", "Status", "Tamanho"])
        self._table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self._table)

    def _toggle_proxy(self, checked: bool) -> None:
        if checked:
            QMessageBox.information(
                self,
                "Proxy",
                "Configure o dispositivo para usar proxy 127.0.0.1:8080 e instale o certificado CA do mitmproxy.",
            )
            self._proxy = start_proxy(self._bus)
        else:
            stop_proxy(self._proxy)
            self._proxy = None

    def _append(self, event: NetworkEvent) -> None:
        self._events.append(event)
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._table.setItem(row, 0, QTableWidgetItem(event.host))
        self._table.setItem(row, 1, QTableWidgetItem(event.method))
        self._table.setItem(row, 2, QTableWidgetItem(str(event.status)))
        self._table.setItem(row, 3, QTableWidgetItem(str(event.size)))

    def _export(self) -> None:
        if not self._events:
            QMessageBox.information(self, "Exportação", "Nenhum dado para exportar.")
            return
        json_p = export_network_json(self._events)
        har_p = export_network_har(self._events)
        QMessageBox.information(self, "Exportação", f"Arquivos salvos em:\n{json_p}\n{har_p}")
