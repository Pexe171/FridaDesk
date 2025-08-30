# Arquitetura e Stack Tecnológico

## Linguagem Principal
- Python 3.10+

## Framework GUI
- PyQt6 / PySide6 (preferência pelo PyQt6 devido a licenças flexíveis para projetos de código aberto e recursos modernos).

## Core de Instrumentação
- frida, frida-tools.

## Comunicação Assíncrona
- Utilizar asyncio e aioqt para garantir que a UI não congele durante operações de I/O (comunicação com Frida, leitura de arquivos). A lógica do core deve ser desacoplada da UI através de sinais e slots (padrão do Qt).

## Estilização
- Utilizar folhas de estilo QSS ou bibliotecas como qt-material para um visual moderno e temas (claro/escuro).

## Empacotamento
- PyInstaller ou Nuitka para criar executáveis independentes.

## Estrutura de Diretórios Proposta

```
|-- main.py             # Ponto de entrada da aplicação
|-- core/
|   |-- __init__.py
|   |-- device_manager.py # Lógica para listar e conectar a dispositivos/processos
|   |-- session.py        # Gerencia uma sessão Frida ativa (attach, detach, script)
|   `-- message_handler.py# Processa mensagens de/para os scripts
|-- ui/
|   |-- __init__.py
|   |-- main_window.py    # Janela principal da aplicação (layout)
|   |-- widgets/          # Componentes reutilizáveis (editor, console, lista de processos)
|   `-- assets/           # Ícones, fontes, etc.
|-- scripts/              # Exemplos de scripts Frida (.js)
|-- plugins/              # Diretório para plugins de usuários
|-- logs/                 # Destino para logs exportados
`-- settings.json         # Arquivo para configurações persistentes
```

Autor: Pexe (Instagram: [@David.devloli](https://instagram.com/David.devloli))
