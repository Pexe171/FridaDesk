"""Testes para portas padrão do DeviceManager.

Autor: Pexe (Instagram: @David.devloli)
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

# ruff: noqa: E402

from core.device_manager import DeviceManager


def test_known_port_ranges_cover_common_emulators():
    dm = DeviceManager()
    ports = dm._known_ports
    # BlueStacks/LDPlayer/Genymotion
    assert 5555 in ports and 5557 in ports
    # Nox Player
    assert 62001 in ports and 62003 in ports
    # MEmu
    assert 21503 in ports and 21513 in ports
