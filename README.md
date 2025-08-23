# FridaHub

Solução inicial contendo os projetos base para o aplicativo Avalonia.

## Estrutura
- **FridaHub.App**: aplicativo Avalonia.
- **FridaHub.Core**: biblioteca de classes principal.
- **FridaHub.Infrastructure**: acesso a dados e configurações.
- **FridaHub.Processes**: processos de negócio.
- **FridaHub.Codeshare**: componentes compartilhados.

## Pré-requisitos
- SDK do .NET 8 instalado.
- ADB disponível no PATH.
- Frida CLI instalada.

## Como compilar
```bash
dotnet build
```

## Como executar
```bash
dotnet run --project src/FridaHub.App
```

## Como executar os testes
```bash
dotnet test
```

## Execução do CodeShare
```bash
dotnet run --project src/FridaHub.Codeshare
```

## Logs
Os logs são gravados na pasta configurada em *Settings* (padrão: diretório `FridaHub` dentro de `~/.local/share`).

## Limitações
- Funções de jailbreak desabilitadas por padrão.
- Scripts e instaladores fornecidos apenas como placeholders.

## Teste de conexão

```csharp
// using var provider = services.BuildServiceProvider();
// using var db = provider.GetRequiredService<FridaHubDbContext>();
// await db.Database.CanConnectAsync();
```

## Autor
Pexe — [instagram.com/David.devloli](https://www.instagram.com/David.devloli)
