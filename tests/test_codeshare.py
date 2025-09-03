import sys
from pathlib import Path
import urllib.request

sys.path.append(str(Path(__file__).resolve().parents[1]))

from core.codeshare import extract_codeshare_slug, download_codeshare_script


class FakeResponse:
    def __init__(self, data: str) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data.encode()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_extract_slug_variants():
    cmd = "frida --codeshare user/script -f target"
    cmd2 = "$ frida --codeshare user/script -f target"
    url = "https://frida.codeshare.io/user/script"
    assert extract_codeshare_slug(cmd) == "user/script"
    assert extract_codeshare_slug(cmd2) == "user/script"
    assert extract_codeshare_slug(url) == "user/script"


def test_download(monkeypatch):
    def fake_urlopen(req):
        assert req.full_url == "https://frida.codeshare.io/user/script.js"
        return FakeResponse("send('ok')")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    code = download_codeshare_script("user/script")
    assert code == "send('ok')"
