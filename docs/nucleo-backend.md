# Núcleo do Back-end (Electron Main)

Documento descrevendo os processos e serviços que orquestram o núcleo do aplicativo.

## 1. Processo Principal

- **Ciclo de vida**: inicia ao `app.whenReady`, cria a janela principal e encerra quando todas as janelas fecham.
- **Janela**: instancia `BrowserWindow` com contexto isolado e uso mínimo de permissões.
- **Preload**: carrega script com `contextBridge` para expor APIs seguras de IPC ao renderer.

## 2. Módulos Isolados

### 2.1 ADB Service

- Lista dispositivos conectados.
- Conecta via TCP/IP (`adb tcpip`, `adb connect`).
- Instala APKs em dispositivos selecionados.
- Operações enfileiradas com _backoff_ para lidar com falhas do daemon ADB.

### 2.2 Frida Service (frida-node)

- Lista processos disponíveis no dispositivo.
- `spawn/attach` em alvos definidos.
- Injeta scripts e roteia mensagens/erros para o renderer.
- Encerra sessões sob demanda e reconecta em `session.detached`.
- Instala e inicializa automaticamente o `frida-server` conforme a arquitetura do dispositivo.

### 2.3 Scripts Service

- CRUD local de scripts: nome, tags, origem, código‑fonte e favorito.
- Armazena metadados para busca rápida.

### 2.4 Execuções/Logs Service

- Registra início/fim das execuções e mantém log em JSONL.
- Stream em tempo real para o renderer via IPC.
- Exporta logs em JSONL ou TXT.
- Possui _circuit‑breaker_ para evitar floods de log.

### 2.5 Config Service

- Persiste tema, cores, caminhos de arquivos e porta da API local.
- Expõe métodos `get/set` via IPC.

### 2.6 Plugins Loader

- Carrega extensões opcionais (CodeShare, métricas etc.).
- Isola cada plugin em sandbox para evitar conflitos.

## 3. Tolerância a Falhas

- Fila com _backoff_ para comandos ADB.
- Reconexão automática de sessões Frida ao receber `session.detached`.
- _Circuit‑breaker_ para fluxos de log excessivos.

---

Autor: Pexe (instagram: @David.devloli)
