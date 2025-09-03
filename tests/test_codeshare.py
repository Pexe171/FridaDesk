import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

import core.codeshare as codeshare  # noqa: E402


def test_extrair_identificador_comando():
    cmd = "frida --codeshare usuario/script -f bin"
    assert codeshare.extrair_identificador(cmd) == "usuario/script"


def test_extrair_identificador_url():
    url = "https://codeshare.frida.re/@usuario/script.js"
    assert codeshare.extrair_identificador(url) == "usuario/script"


def test_baixar_script(monkeypatch):
    captura = {}

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b"console.log('oi')"

    def fake_urlopen(url):
        captura["url"] = url
        return FakeResp()

    monkeypatch.setattr(codeshare, "urlopen", fake_urlopen)
    codigo = codeshare.baixar_script("usuario/script")
    assert "console.log" in codigo
    assert captura["url"] == "https://codeshare.frida.re/@usuario/script.js"
