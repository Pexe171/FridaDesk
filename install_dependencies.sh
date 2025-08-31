#!/usr/bin/env bash
# Autor: Pexe (instagram: David.devloli)
# Script para instalar todas as dependências necessárias de uma vez.
set -e
python -m pip install --upgrade pip
pip install -r requirements.txt
