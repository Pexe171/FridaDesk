"""Diálogo de opções para dispositivos.

Autor: Pexe (Instagram: @David.devloli)
"""

from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QPushButton,
    QMessageBox,
)


class DeviceOptionsDialog(QDialog):
    """Exibe opções ao selecionar um dispositivo."""

    def __init__(self, device_name: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(device_name)
        layout = QVBoxLayout(self)

        self._graph_btn = QPushButton("Gráfico")
        self._graph_btn.clicked.connect(lambda: self._not_implemented("Gráfico"))
        layout.addWidget(self._graph_btn)

        self._json_btn = QPushButton("JSON")
        self._json_btn.clicked.connect(lambda: self._not_implemented("JSON"))
        layout.addWidget(self._json_btn)

        self._raw_btn = QPushButton("Raw")
        self._raw_btn.clicked.connect(lambda: self._not_implemented("Raw"))
        layout.addWidget(self._raw_btn)

        self._script_btn = QPushButton("Scripts")
        self._script_btn.clicked.connect(lambda: self._not_implemented("Scripts"))
        layout.addWidget(self._script_btn)

        self._conn_btn = QPushButton("Conexões")
        self._conn_btn.clicked.connect(lambda: self._not_implemented("Conexões"))
        layout.addWidget(self._conn_btn)

        self._net_btn = QPushButton("Eventos de Rede")
        self._net_btn.clicked.connect(lambda: self._not_implemented("Eventos de Rede"))
        layout.addWidget(self._net_btn)

        self._proxy_btn = QPushButton("Ativar Proxy")
        self._proxy_btn.clicked.connect(lambda: self._not_implemented("Ativar Proxy"))
        layout.addWidget(self._proxy_btn)

        self._export_btn = QPushButton("Exportar")
        self._export_btn.clicked.connect(lambda: self._not_implemented("Exportar"))
        layout.addWidget(self._export_btn)

    def _not_implemented(self, feature: str) -> None:
        QMessageBox.information(self, feature, f"Ação '{feature}' não implementada.")

