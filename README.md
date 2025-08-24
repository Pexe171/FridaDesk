# FridaDesk

FridaDesk é um projeto inicial para experimentos com Electron, React, sql.js e frida.

## Visão

Criar uma plataforma de desenvolvimento segura e colaborativa para integrar ferramentas de análise e automação.

## Requisitos

- Node.js 18+
- NPM
- Git

## Começando

1. Instale dependências: `npm install`
2. Copie `.env.example` para `.env` e ajuste os valores.
3. Execute em desenvolvimento web: `npm run dev`
4. Para rodar a aplicação desktop, use: `npm start`

## Scripts

- `npm run dev` – executa o ambiente de desenvolvimento
- `npm start` – compila e inicia a aplicação Electron
- `npm run build` – gera build (placeholder)
- `npm run lint` – roda ESLint e Prettier
- `npm test` – executa testes com Jest

## Branching

- `main`: código estável
- `dev`: integração
- `feature/*`: novas funcionalidades

## ADR

As decisões de arquitetura estão em [`docs/adr`](docs/adr).

## Autor

Mantido por **Pexe** (Instagram [@David.devloli](https://instagram.com/David.devloli)).

## Licença

MIT - veja [LICENSE](LICENSE).
