# Contratos de IPC (Front ↔ Main)

Documento acordado entre times de front e back para padronizar a comunicação via IPC.

## 1. Canais

- **devices:list** → lista de dispositivos.
- **adb:connect** / **adb:tcpip** / **adb:install**.
- **frida:processes** / **frida:runScript** / **frida:stop**.
- **scripts:list** / **scripts:import** / **scripts:delete**.
- **history:list** / **history:export**.
- **config:get** / **config:set**.
- Eventos: **exec:log** (stream de mensagens) e **exec:event** (started/stopped/error).

## 2. Payloads

Todos os payloads usam JSON com campos:

- Strings, números e arrays conforme a função.
- Campos obrigatórios explicitados, demais opcionais.
- Exemplo `devices:list`: resposta `{ ok: true, devices: [{ id, name }] }`.

## 3. Erros

Formato unificado: `{ ok: false, error: "mensagem" }` com mensagens curtas.

## 4. Timeouts e Retry

O front aplica timeout de 10 s com feedback ao usuário e pode tentar novamente.

## 5. Versionamento

`config:get` inclui campo `appVersion` para sincronizar mudanças de contrato.

---

Autor: Pexe (instagram: @David.devloli)
