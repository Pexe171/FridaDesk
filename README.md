# FridaDesk

Projeto exemplo em Java que automatiza a abertura do Minecraft e executa comandos do mod Baritone.

Mantido por **Pexe** (Instagram [@David.devloli](https://instagram.com/David.devloli)).

## Pré-requisitos
- Java 17 ou superior
- Minecraft instalado com o mod Baritone
- Launcher do Minecraft configurado no sistema ("minecraft-launcher" no PATH) ou caminho fornecido no `config.json`

## Como compilar
```bash
javac -d bin src/*.java
```

## Como executar
```bash
java -cp bin Main
```

## Configuração
Edite o arquivo `config.json` para ajustar:
- `minecraftVersion`: versão do jogo a ser carregada (ex: `"1.21"`).
- `gameDir`: diretório de instalação do Minecraft.
- `launcherPath`: caminho completo do executável do launcher (opcional se estiver no PATH).
- `baritoneCommand`: comando a ser enviado após o carregamento do mundo (ex: `".mine diamond_ore"`).

## Observações
- O tempo de espera para o carregamento do mundo pode ser ajustado em `BaritoneCommander.java`.
- Caso o launcher não esteja no PATH, informe seu caminho em `launcherPath` no `config.json`.
