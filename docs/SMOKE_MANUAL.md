# Bloco 25 — Roteiro de Smoke Teste

## 25.1 Sem ADB/Frida
- Execute `dotnet run --project src/FridaHub.App`.
- A lista de dispositivos deve aparecer vazia.
- Ao tentar executar um script, a aplicação deve exibir um erro amigável.

## 25.2 Com ADB e device/emulador
- Inicie o ADB e conecte um aparelho físico ou emulador.
- A lista de dispositivos deve listar o aparelho conectado.
- Rode um script simples do CodeShare, por exemplo, um que apenas enumere classes, e observe os logs.

## 25.3 Histórico
- Abra a aba **Histórico**.
- Selecione uma execução anterior e abra o arquivo JSONL correspondente.

**Aceite:** a aplicação deve se comportar conforme o roteiro acima.
