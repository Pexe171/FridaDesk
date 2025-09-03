"""Funções utilitárias para integração com o CodeShare do Frida.

Autor: Pexe (Instagram: @David.devloli)
"""

from __future__ import annotations

import re
from urllib.request import urlopen

CODESHARE_BASE = "https://codeshare.frida.re"


def extrair_identificador(texto: str) -> str:
    """Extrai o identificador de um comando, URL ou slug do CodeShare.

    Exemplos aceitos:
    - ``frida --codeshare usuario/script -f binario``
    - ``https://codeshare.frida.re/@usuario/script.js``
    - ``usuario/script``
    """

    texto = texto.strip()
    match = re.search(r"--codeshare\s+([^\s]+)", texto)
    if match:
        return match.group(1)

    match = re.search(r"codeshare\.frida\.re/@?([^\.\s]+(?:/[^\.\s]+)?)", texto)
    if match:
        return match.group(1)

    return texto


def baixar_script(texto: str) -> str:
    """Baixa e retorna o script de um item do CodeShare."""

    ident = extrair_identificador(texto)
    url = f"{CODESHARE_BASE}/@{ident}.js"
    with urlopen(url) as resp:
        return resp.read().decode("utf-8")
