"""Utilidades para carregar scripts do CodeShare.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import re
import urllib.request
from typing import Optional


_CODESHARE_RAW_URL = "https://frida.codeshare.io/{slug}.js"


def extract_codeshare_slug(text: str) -> Optional[str]:
    """Extrai o identificador ``autor/script`` a partir de ``text``.

    Aceita comandos completos (``frida --codeshare autor/script``), URLs ou
    apenas o próprio identificador.
    """

    text = text.strip()
    if not text:
        return None

    # Remove prompt inicial "$" se existir
    if text.startswith("$"):
        text = text[1:].strip()

    # Busca padrão --codeshare
    match = re.search(r"--codeshare\s+([\w\-./@]+)", text)
    if match:
        text = match.group(1)

    # Remove protocolo e domínio de URLs conhecidos
    text = re.sub(
        r"^(https?://)?(frida\.codeshare\.io|codeshare\.frida\.re)/@?",
        "",
        text,
        flags=re.IGNORECASE,
    )

    # Remove possíveis parâmetros e versões
    text = text.split("?")[0]
    parts = [p for p in text.split("/") if p]
    if len(parts) < 2:
        return None
    return "/".join(parts[:2])


def download_codeshare_script(identifier: str) -> str:
    """Baixa o script correspondente a ``identifier`` do CodeShare."""

    slug = extract_codeshare_slug(identifier)
    if slug is None:
        raise ValueError("Identificador CodeShare inválido")
    url = _CODESHARE_RAW_URL.format(slug=slug)
    req = urllib.request.Request(url, headers={"User-Agent": "FridaDesk"})
    with urllib.request.urlopen(req) as response:  # nosec - URL controlada
        return response.read().decode("utf-8")
