# Pré-requisitos & versões (Android + Frida)

## 0.1 Alinhamento de versões Frida

| Versão host (frida-node) | Versão frida-server | Observações |
| --- | --- | --- |
| 17.x | 17.x | Manter major igual. Conferir [release notes](https://frida.re/news/) para mudanças de compatibilidade. |

## 0.2 Estratégia em Android

- **Com root**: iniciar `frida-server` via ADB para `attach` ou `spawn` direto. Referência [HackTricks](https://book.hacktricks.xyz/mobile-apps-pentesting/android-app-pentesting/frida-tips).
- **Sem root**: avaliar uso do [Frida Gadget](https://frida.re/docs/gadget/) embutido no app ou reempacotamento em pipeline de QA. Ver [LearnFrida](https://learnfrida.info/) para alternativas.

## 0.3 Mapeamento de ABI

| ABI Android | Binário frida-server |
| --- | --- |
| arm64-v8a | frida-server-*-android-arm64 |
| armeabi-v7a | frida-server-*-android-arm |
| x86_64 | frida-server-*-android-x86_64 |
| x86 | frida-server-*-android-x86 |

## 0.4 Checklist ADB

1. `adb devices` lista emuladores/ dispositivos.
2. Habilitar modo TCP/IP quando necessário: `adb tcpip 5555`.
3. Operações usam timeout padrão de 10 s.

## Procedimento start/stop do frida-server (emuladores dev/QA)

**Start**

1. `adb push frida-server-17.x.x-android-<abi> /data/local/tmp/`
2. `adb shell "chmod 755 /data/local/tmp/frida-server-17.x.x-android-<abi>"`
3. `adb shell "/data/local/tmp/frida-server-17.x.x-android-<abi> &"`

**Stop**

- `adb shell pkill -f frida-server`

---

Autor: Pexe (instagram: @David.devloli)
