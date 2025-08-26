# Guia de Layout e Espaçamento do FridaDesk

Autor: Pexe (instagram: [@David.devloli](https://instagram.com/David.devloli))

## Grid base

- A interface utiliza uma grade com barra lateral fixa de 240px e área principal flexível.
- Em telas menores que 768px, a barra lateral é reduzida para 60px para maximizar o espaço de conteúdo.

## Espaçamentos

- Utilize os tokens `--espaco-xs`, `--espaco-sm`, `--espaco-md`, `--espaco-lg` e `--espaco-xl` definidos em `src/styles/tokens.css`.
- Margens e paddings devem seguir esses tokens para garantir consistência.

## Componentes

- Botões, cards, tabelas e outros componentes devem usar os tokens de espaçamento e os raios `--raio-sm`, `--raio-md` ou `--raio-lg` conforme necessário.
- O alinhamento padrão é realizado com Flexbox ou CSS Grid para manter o layout fluido.

## Responsividade

- O layout deve se adaptar a diferentes tamanhos de tela, mantendo legibilidade e usabilidade.
- Breakpoints principais: 768px para dispositivos móveis e 1024px para telas maiores.

