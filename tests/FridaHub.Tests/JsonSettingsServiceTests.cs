using FridaHub.Core.Models;
using FridaHub.Infrastructure.Services;

namespace FridaHub.Tests;

public class JsonSettingsServiceTests
{
    [Fact]
    public async Task LoadAsync_DeveRetornarPadraoQuandoNaoExisteArquivo()
    {
        var temp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString(), "settings.json");
        var service = new JsonSettingsService(temp);

        var result = await service.LoadAsync();

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task SaveAsync_DevePersistirConfiguracoes()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        var file = Path.Combine(tempDir, "settings.json");
        var service = new JsonSettingsService(file);
        var settings = new Settings { LogsFolder = "/tmp", ShowElevatedTargets = true };

        var save = await service.SaveAsync(settings);
        Assert.True(save.IsSuccess);

        var load = await service.LoadAsync();
        Assert.True(load.IsSuccess);
        Assert.Equal("/tmp", load.Value!.LogsFolder);
        Assert.True(load.Value!.ShowElevatedTargets);
    }
}
