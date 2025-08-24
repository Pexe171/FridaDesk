# Contratos de IPC (Front ↔ Main)

Documento acordado entre times de front e back para padronizar a comunicação via IPC.

## 1. Canais e Payloads

| Canal | Requisição | Resposta | Erros (códigos) | Timeout |
|------|------------|----------|-----------------|---------|
| `devices:list` | `-` | `{ ok: true, devices: [{ id, name }] }` | `E_ADB_OFFLINE` | 10 s |
| `adb:connect` | `{ id }` | `{ ok: true }` | `E_DEVICE_NOT_FOUND`, `E_ADB_ERROR` | 10 s |
| `adb:install` | `{ id, apkPath }` | `{ ok: true }` | `E_INSTALL_FAILED` | 30 s |
| `frida:processes` | `{ deviceId? }` | `{ ok: true, processes: [{ pid, name }] }` | `E_FRIDA_ERROR` | 10 s |
| `frida:runScript` | `{ deviceId, target, script }` | `{ ok: true, execId }` | `E_PROCESS_NOT_FOUND`, `E_SCRIPT_ERROR` | 10 s |
| `frida:stop` | `{ execId }` | `{ ok: true }` | `E_EXEC_NOT_FOUND` | 10 s |
| `scripts:list` | `-` | `{ ok: true, scripts: [...] }` | `E_IO` | 5 s |
| `scripts:import` | `{ name, source, tags[] }` | `{ ok: true, id }` | `E_VALIDATION`, `E_IO` | 5 s |
| `scripts:delete` | `{ id }` | `{ ok: true }` | `E_SCRIPT_NOT_FOUND` | 5 s |
| `history:list` | `{ limit }` | `{ ok: true, executions: [...] }` | `E_IO` | 5 s |
| `history:export` | `{ format, path }` | `{ ok: true, file }` | `E_IO`, `E_EXPORT_FAILED` | 30 s |
| `config:get` | `{ key? }` | `{ ok: true, value | config }` | `E_CONFIG_NOT_FOUND` | 5 s |
| `config:set` | `{ key, value }` | `{ ok: true }` | `E_CONFIG_INVALID` | 5 s |

### Eventos

| Evento | Payload |
|--------|---------|
| `exec:log` | `{ execId, message }` |
| `exec:event` | `{ execId, type: 'started' | 'stopped' | 'error', data? }` |

## 2. Códigos de Erro

- `E_ADB_OFFLINE`: daemon ADB não respondeu.
- `E_DEVICE_NOT_FOUND`: dispositivo não encontrado.
- `E_ADB_ERROR`: erro genérico do ADB.
- `E_INSTALL_FAILED`: falha na instalação do APK.
- `E_FRIDA_ERROR`: operação Frida falhou.
- `E_PROCESS_NOT_FOUND`: processo alvo não encontrado.
- `E_SCRIPT_ERROR`: script inválido ou falha de execução.
- `E_EXEC_NOT_FOUND`: execução não encontrada.
- `E_IO`: erro de leitura ou escrita.
- `E_VALIDATION`: dados de entrada inválidos.
- `E_SCRIPT_NOT_FOUND`: script não encontrado.
- `E_EXPORT_FAILED`: falha ao exportar histórico.
- `E_CONFIG_NOT_FOUND`: chave de configuração inexistente.
- `E_CONFIG_INVALID`: valor de configuração inválido.

## 3. Timeouts e Retry

O front aplica timeout padrão de 10 s e tenta novamente em falhas transitórias. Operações de instalação e exportação usam 30 s.

## 4. Versionamento

`config:get` inclui campo `appVersion` para sincronizar mudanças de contrato.

---

Autor: Pexe (instagram: @David.devloli)
