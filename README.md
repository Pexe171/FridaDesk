# Frida GUI Dashboard

Repositório oficial do **Frida GUI Dashboard**, uma aplicação de desktop multi-plataforma destinada a facilitar a instrumentação dinâmica com o Frida.

## Stack
- Python 3.10+
- PyQt6
- qasync
- ADB (subprocess ou pure-python-adb)
- mitmproxy (opcional)
- pydantic
- loguru
- PyInstaller

Para mais detalhes sobre objetivos, foco e público-alvo, consulte [docs/visao_geral.md](docs/visao_geral.md).

## Recursos

- Detecção automática de dispositivos ADB (USB e emuladores) com atualização em tempo real e cadastro de endpoints remotos.
- Carregamento automático de scripts do CodeShare ao colar comandos
  `frida --codeshare autor/script` no editor de scripts.

Autor: Pexe (Instagram: [@David.devloli](https://instagram.com/David.devloli))
