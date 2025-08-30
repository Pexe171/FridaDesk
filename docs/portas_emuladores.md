# Portas padrão em emuladores Android

Este documento resume as portas mais comuns utilizadas por emuladores Android e pelo ADB. As informações ajudam na implementação de rotinas de comunicação de rede no sistema.

## Emuladores e portas ADB

| Emulador          | Porta ADB padrão | Observações |
|-------------------|------------------|-------------|
| **BlueStacks**    | 5555             | Acesso via `127.0.0.1:5555`. Instâncias adicionais podem usar portas pares/ímpares sequenciais. |
| **Nox Player**    | 62001            | Cada instância inicia em `127.0.0.1:62001`, com incremento de 2 para múltiplas instâncias (`62001`, `62003`, ...). |
| **MEmu**          | 21503            | Usa `127.0.0.1:21503` para ADB; instâncias adicionais incrementam a porta. |
| **LDPlayer**      | 5555             | Normalmente expõe ADB em `127.0.0.1:5555`. |
| **Genymotion**    | 5555             | Conexão típica em `127.0.0.1:5555`. |
| **Android Studio (AVD)** | 5554/5555 | O console usa porta par (ex.: `5554`) e o ADB usa a porta ímpar seguinte (`5555`). |

## Portas relacionadas ao ADB

* **5037** – Porta do servidor ADB no host.
* **5555** – Porta padrão para depuração via rede.

## Referências

Autor: Pexe (Instagram: @David.devloli)
