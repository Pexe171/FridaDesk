#!/usr/bin/env bash
# Autor: Pexe (instagram: David.devloli)
# Este script instala todas as dependências necessárias para o FridaDesk.

set -e

pip install \
    PyQt6 \
    qasync \
    mitmproxy \
    jinja2 \
    pydantic \
    pyqtgraph \
    matplotlib \
    ruff \
    mypy \
    pytest \
    pyinstaller
