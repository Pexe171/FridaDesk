using System.Text.RegularExpressions;
using FridaHub.Core.Backends;
using FridaHub.Core.Models;
using FridaHub.Core.Results;

namespace FridaHub.Processes;

/// <summary>
/// Backend de ADB baseado em execução de processos.
/// </summary>
public class AdbService : IAdbBackend
{
    private readonly ProcessRunner _runner;

    public AdbService(ProcessRunner runner)
    {
        _runner = runner;
    }

    public static DeviceInfo Parse(string serial, Dictionary<string, string> props)
    {
        var isEmu = props.TryGetValue("ro.kernel.qemu", out var qemu) && qemu == "1";
        var model = props.TryGetValue("ro.product.manufacturer", out var manuf) ? manuf + " " : string.Empty;
        if (props.TryGetValue("ro.product.model", out var m))
            model += m;
        return new DeviceInfo
        {
            Serial = serial,
            Model = model.Trim(),
            IsEmulator = isEmu,
            Platform = DevicePlatform.Android,
            Props = props,
            LastSeenUtc = DateTime.UtcNow
        };
    }

    public async Task<Result> StartServerAsync()
    {
        try
        {
            var run = _runner.Run("adb", "start-server");
            await foreach (var _ in run.Output) { }
            var exit = await run.WaitForExitAsync();
            return exit == 0
                ? Result.Success()
                : Result.Failure($"adb retornou código {exit}");
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    public async Task<Result<IEnumerable<DeviceInfo>>> ListDevicesAsync()
    {
        try
        {
            var run = _runner.Run("adb", "devices -l");
            var lines = new List<string>();
            await foreach (var line in run.Output)
                lines.Add(line.Line);
            var exit = await run.WaitForExitAsync();
            if (exit != 0)
                return Result<IEnumerable<DeviceInfo>>.Failure($"adb retornou código {exit}");

            var devices = new List<DeviceInfo>();
            foreach (var line in lines.Skip(1)) // ignora cabeçalho
            {
                var match = Regex.Match(line, "^(?<serial>\\S+)\\s+device");
                if (!match.Success) continue;
                var serial = match.Groups["serial"].Value;
                var propsResult = await GetPropsAsync(serial);
                var props = propsResult.IsSuccess ? propsResult.Value! : new Dictionary<string, string>();
                devices.Add(Parse(serial, props));
            }

            return Result<IEnumerable<DeviceInfo>>.Success(devices);
        }
        catch (Exception ex)
        {
            return Result<IEnumerable<DeviceInfo>>.Failure(ex.Message);
        }
    }

    public async Task<Result<Dictionary<string, string>>> GetPropsAsync(string serial)
    {
        try
        {
            var props = new Dictionary<string, string>();
            foreach (var key in new[] { "ro.product.model", "ro.product.manufacturer", "ro.kernel.qemu" })
            {
                var run = _runner.Run("adb", $"-s {serial} shell getprop {key}");
                string? value = null;
                await foreach (var line in run.Output)
                {
                    if (!string.IsNullOrWhiteSpace(line.Line))
                    {
                        value = line.Line.Trim();
                        break;
                    }
                }
                await run.WaitForExitAsync();
                props[key] = value ?? string.Empty;
            }

            return Result<Dictionary<string, string>>.Success(props);
        }
        catch (Exception ex)
        {
            return Result<Dictionary<string, string>>.Failure(ex.Message);
        }
    }

    public async Task<Result<string>> GetPropAsync(string serial, string key)
    {
        try
        {
            var run = _runner.Run("adb", $"-s {serial} shell getprop {key}");
            string? value = null;
            await foreach (var line in run.Output)
            {
                if (!string.IsNullOrWhiteSpace(line.Line))
                {
                    value = line.Line.Trim();
                    break;
                }
            }
            var exit = await run.WaitForExitAsync();
            return exit == 0
                ? Result<string>.Success(value ?? string.Empty)
                : Result<string>.Failure($"adb retornou código {exit}");
        }
        catch (Exception ex)
        {
            return Result<string>.Failure(ex.Message);
        }
    }

    public async Task<Result> ForwardPortsAsync(string serial, int localPort, int remotePort)
    {
        try
        {
            var run = _runner.Run("adb", $"-s {serial} forward tcp:{localPort} tcp:{remotePort}");
            await foreach (var _ in run.Output) { }
            var exit = await run.WaitForExitAsync();
            return exit == 0
                ? Result.Success()
                : Result.Failure($"adb retornou código {exit}");
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }
}

