# FridaDesk

Projeto exemplo em Java que automatiza a abertura do Minecraft e executa comandos do mod Baritone.

Mantido por **Pexe** (Instagram [@David.devloli](https://instagram.com/David.devloli)).

## Pré-requisitos
- Java 17 ou superior
- Minecraft instalado com o mod Baritone
- Launcher do Minecraft configurado no sistema ("minecraft-launcher" no PATH)

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
- `launcherPath`: caminho completo para o executável do launcher (opcional; se vazio, usa-se `minecraft-launcher`).
- `baritoneCommand`: comando a ser enviado após o carregamento do mundo (ex: `".mine diamond_ore"`).

## Observações
- O tempo de espera para o carregamento do mundo pode ser ajustado em `BaritoneCommander.java`.
- O caminho do launcher pode ser alterado em `LauncherHandler.java`.
