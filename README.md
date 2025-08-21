# FridaHub

Solução inicial contendo os projetos base para o aplicativo Avalonia.

## Estrutura
- **FridaHub.App**: aplicativo Avalonia.
- **FridaHub.Core**: biblioteca de classes principal.
- **FridaHub.Infrastructure**: acesso a dados e configurações.
- **FridaHub.Processes**: processos de negócio.
- **FridaHub.Codeshare**: componentes compartilhados.

## Como compilar
```bash
dotnet build
```

## Teste do banco de dados
```csharp
using var db = new FridaHub.Infrastructure.FridaHubDbContext();
await db.Database.CanConnectAsync();
```

## Autor
Pexe — [instagram.com/David.devloli](https://www.instagram.com/David.devloli)
