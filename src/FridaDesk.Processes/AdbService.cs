using FridaDesk.Core.Backends;
using FridaDesk.Core.Models;
using FridaDesk.Core.Results;

namespace FridaDesk.Processes;

/// <summary>
/// Backend ADB com resultados fictícios.
/// </summary>
public class AdbService : IAdbBackend
{
    private readonly ProcessRunner _runner;

    public AdbService(ProcessRunner runner)
    {
        _runner = runner;
    }

    public Task<Result> StartServerAsync()
        => Task.FromResult(Result.Success());

    public Task<Result<IEnumerable<DeviceInfo>>> ListDevicesAsync()
    {
        var device = new DeviceInfo
        {
            Serial = "emulator-5554",
            Model = "Emulador",
            IsEmulator = true,
            Platform = DevicePlatform.Android,
            LastSeenUtc = DateTime.UtcNow
        };
        return Task.FromResult(Result<IEnumerable<DeviceInfo>>.Success(new[] { device }));
    }

    public Task<Result<Dictionary<string, string>>> GetPropsAsync(string serial)
    {
        var props = new Dictionary<string, string>
        {
            ["ro.product.model"] = "Pixel",
            ["ro.product.manufacturer"] = "Google"
        };
        return Task.FromResult(Result<Dictionary<string, string>>.Success(props));
    }

    public Task<Result<string>> GetPropAsync(string serial, string key)
        => Task.FromResult(Result<string>.Success(""));

    public Task<Result> ForwardPortsAsync(string serial, int localPort, int remotePort)
        => Task.FromResult(Result.Success());
}
