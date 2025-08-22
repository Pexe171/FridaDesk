using FridaHub.Core.Backends;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Results;
using SharpCompress.Compressors.Xz;
using System.Net.Http;

namespace FridaHub.Processes;

public class FridaInstaller : IFridaInstaller
{
    private readonly IAdbBackend _adb;
    private readonly ProcessRunner _runner;
    private readonly HttpClient _http;
    private const string Version = "16.7.7";

    public FridaInstaller(IAdbBackend adb, ProcessRunner runner, HttpClient? httpClient = null)
    {
        _adb = adb;
        _runner = runner;
        _http = httpClient ?? new HttpClient();
    }

    public async Task<Result> InstallAsync(string serial)
    {
        try
        {
            var binResult = await GetServerBinaryNameAsync(serial);
            if (!binResult.IsSuccess || string.IsNullOrWhiteSpace(binResult.Value))
                return Result.Failure("ABI não suportada");
            var binaryName = binResult.Value!;
            var localPathResult = await EnsureBinaryAsync(binaryName);
            if (!localPathResult.IsSuccess)
                return Result.Failure(localPathResult.Error!.Message);
            var localPath = localPathResult.Value!;

            await RunAdbAsync($"-s {serial} push \"{localPath}\" /data/local/tmp/frida-server");
            await RunAdbAsync($"-s {serial} shell chmod +x /data/local/tmp/frida-server");
            await RunAdbAsync($"-s {serial} shell \"nohup /data/local/tmp/frida-server >/dev/null 2>&1 &\"");
            await _adb.ForwardPortsAsync(serial, 27042, 27042);
            await _adb.ForwardPortsAsync(serial, 27043, 27043);

            var running = await IsRunningAsync(serial);
            return running ? Result.Success() : Result.Failure("frida-server não iniciou");
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    internal async Task<Result<string>> GetServerBinaryNameAsync(string serial)
    {
        var props = new[]
        {
            await _adb.GetPropAsync(serial, "ro.product.cpu.abi"),
            await _adb.GetPropAsync(serial, "ro.product.cpu.abilist"),
            await _adb.GetPropAsync(serial, "ro.product.cpu.arch")
        };

        string? abi = props.FirstOrDefault(p => p.IsSuccess && !string.IsNullOrWhiteSpace(p.Value))?.Value;
        abi = abi?.Split(',').FirstOrDefault();

        return abi switch
        {
            "arm64-v8a" => Result<string>.Success($"frida-server-{Version}-android-arm64"),
            "armeabi-v7a" => Result<string>.Success($"frida-server-{Version}-android-arm"),
            "x86" => Result<string>.Success($"frida-server-{Version}-android-x86"),
            "x86_64" => Result<string>.Success($"frida-server-{Version}-android-x86_64"),
            _ => Result<string>.Failure("ABI desconhecida")
        };
    }

    private async Task<Result<string>> EnsureBinaryAsync(string name)
    {
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FridaDesk", "frida-servers");
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, name);
        if (!File.Exists(path))
        {
            var url = $"https://github.com/frida/frida/releases/download/{Version}/{name}.xz";
            using var stream = await _http.GetStreamAsync(url);
            using var xz = new XZStream(stream);
            using var file = File.Create(path);
            await xz.CopyToAsync(file);
        }
        return Result<string>.Success(path);
    }

    private async Task RunAdbAsync(string args)
    {
        var run = _runner.Run("adb", args);
        await foreach (var _ in run.Output) { }
        await run.WaitForExitAsync();
    }

    private async Task<bool> IsRunningAsync(string serial)
    {
        var run = _runner.Run("adb", $"-s {serial} shell ps -A");
        var found = false;
        await foreach (var line in run.Output)
        {
            if (line.Line.Contains("frida-server"))
                found = true;
        }
        await run.WaitForExitAsync();
        return found;
    }
}
