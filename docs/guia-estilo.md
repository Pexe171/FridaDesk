# Guia de Estilo do FridaDesk

Autor: Pexe (instagram: [@David.devloli](https://instagram.com/David.devloli))

## Paleta de cores

- Primária: `#4CAF50`
- Secundária: `#2196F3`
- Fundo: `#0B0F0C`
- Superfície: `#101412`
- Texto: `#E0E0E0`
- Muted: `#8EA390`
- Erro: `#F44336`
- Aviso: `#FFC107`
- Neons: Verde `#39FF14`, Ciano `#00E5FF`

Os tokens estão definidos em `src/styles/tokens.css`.

## Tipografia

Fonte principal: **JetBrains Mono** (fallback `monospace`).

Tamanhos disponíveis:
- `--tamanho-fonte-xs`: 0.75rem
- `--tamanho-fonte-sm`: 0.875rem
- `--tamanho-fonte-md`: 1rem
- `--tamanho-fonte-lg`: 1.125rem
- `--tamanho-fonte-xl`: 1.5rem

Pesos: `--peso-regular` e `--peso-negrito`.

## Componentes base

Estilos disponíveis em `src/styles/componentes.css`.

- **Botões**: `.btn`, `.btn-primary`, `.btn-ghost`
- **Inputs e selects**
- **Chips**: `.chip`
- **Cards**: `.card`
- **Tabelas**: `.tabela`
- **Toasters**: `.toast`, com modificadores `.aviso` e `.erro`

## Estados e acessibilidade

- `:hover`, `:focus`, `:active` com brilho neon.
- Foco visível com `outline` neon.
- Suporte a `prefers-reduced-motion` para reduzir transições.
- Cores escolhidas com contraste AA.

## Ícones e logotipo

Logotipo minimalista com "F" e borda hexagonal neon disponível em `docs/logo.svg`.

## Microinterações

Transições curtas e sutis. Evitar animações exageradas que prejudiquem a leitura.
