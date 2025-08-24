# API Local para Mobile Companion

API HTTP para exposição de dados básicos ao app companion.

## 1. Endpoints

- `GET /api/health` → `{ ok: true, timestamp }`.
- `GET /api/executions?limit=N` → retorna as últimas N execuções.

## 2. Segurança

- Bind em `127.0.0.1` por padrão.
- Opção de token de acesso.
- CORS desativado.

## 3. Rate Limiting

- Limite básico de requisições por minuto.

## 4. Observabilidade

- Logs de requests e contadores simples.

## 5. Evolução

- Planejado suporte a streaming (SSE/WebSocket) para logs ao vivo em fase futura.

## 6. Configuração

- Escopo e porta configuráveis via `config`.

---

Autor: Pexe (instagram: @David.devloli)
