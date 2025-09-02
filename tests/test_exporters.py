import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

# ruff: noqa: E402

from core.exporters import (
    export_logs_csv,
    export_logs_json,
    export_network_json,
    export_network_har,
)
from core.models import LogEvent, NetworkEvent  # noqa: E402


def test_export_logs(tmp_path, monkeypatch):
    import core.exporters as exporters

    monkeypatch.setattr(exporters, "LOG_DIR", tmp_path)
    logs = [LogEvent(ts=1.0, level="INFO", tag="t", message="m", raw="")]
    json_p = export_logs_json(logs)
    csv_p = export_logs_csv(logs)
    assert json_p.exists()
    assert csv_p.exists()


def test_export_network(tmp_path, monkeypatch):
    import core.exporters as exporters

    monkeypatch.setattr(exporters, "LOG_DIR", tmp_path)
    events = [
        NetworkEvent(
            ts=1.0,
            host="h",
            method="GET",
            status=200,
            size=10,
            request="",
            response="",
        )
    ]
    json_p = export_network_json(events)
    har_p = export_network_har(events)
    assert json_p.exists()
    assert har_p.exists()
