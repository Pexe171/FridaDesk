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

## Teste de conexão

```csharp
// using var provider = services.BuildServiceProvider();
// using var db = provider.GetRequiredService<FridaHubDbContext>();
// await db.Database.CanConnectAsync();
```

## Autor
Pexe — [instagram.com/David.devloli](https://www.instagram.com/David.devloli)
