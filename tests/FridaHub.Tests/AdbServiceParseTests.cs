using FridaHub.Processes;
using FridaHub.Core.Models;

namespace FridaHub.Tests;

public class AdbServiceParseTests
{
    [Fact]
    public void Parse_DeveRetornarInformacoesDoDispositivo()
    {
        var props = new Dictionary<string, string>
        {
            {"ro.product.model", "Pixel"},
            {"ro.product.manufacturer", "Google"},
            {"ro.kernel.qemu", "1"}
        };

        var device = AdbService.Parse("emulator-5554", props);

        Assert.Equal("emulator-5554", device.Serial);
        Assert.True(device.IsEmulator);
        Assert.Equal("Google Pixel", device.Model);
        Assert.Equal(DevicePlatform.Android, device.Platform);
    }
}
