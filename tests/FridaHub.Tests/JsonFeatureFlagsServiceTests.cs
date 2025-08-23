using FridaHub.Core.Models;
using FridaHub.Infrastructure.Services;

namespace FridaHub.Tests;

public class JsonFeatureFlagsServiceTests
{
    [Fact]
    public async Task DevePersistirFlags()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        var file = Path.Combine(tempDir, "flags.json");
        var service = new JsonFeatureFlagsService(file);

        var load = await service.LoadAsync();
        Assert.True(load.IsSuccess);
        Assert.False(load.Value!.EnableJailbreakFeature);
        Assert.False(load.Value!.EnableAdvancedProcessList);

        var flags = new FeatureFlags { EnableJailbreakFeature = true, EnableAdvancedProcessList = true };
        var save = await service.SaveAsync(flags);
        Assert.True(save.IsSuccess);

        var service2 = new JsonFeatureFlagsService(file);
        var load2 = await service2.LoadAsync();
        Assert.True(load2.IsSuccess);
        Assert.True(load2.Value!.EnableJailbreakFeature);
        Assert.True(load2.Value!.EnableAdvancedProcessList);
    }
}
