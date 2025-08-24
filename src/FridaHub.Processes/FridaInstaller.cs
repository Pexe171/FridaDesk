using FridaHub.Core.Backends;
using FridaHub.Core.Interfaces;
using SharpCompress.Compressors.Xz;
using System.Net.Http;
using System.IO;
using System.Linq;
using System;

namespace FridaHub.Processes;

// Autor: Pexe (instagram David.devloli)
public class FridaInstaller : IFridaInstaller
{
    private readonly IAdbBackend _adb;
    private readonly ProcessRunner _runner;
    private readonly HttpClient _http;

    public FridaInstaller(IAdbBackend adb, ProcessRunner runner, HttpClient? httpClient = null)
    {
        _adb = adb;
        _runner = runner;
        _http = httpClient ?? new HttpClient();
    }

    public async Task<bool> EnsureAsync(string serial, string version = "16.7.7")
    {
        try
        {
            var binaryName = await GetServerBinaryNameAsync(serial, version);
            if (binaryName is null)
                return false;

            var localPath = await EnsureBinaryAsync(binaryName, version);
            if (localPath is null)
                return false;

            await RunAdbAsync($"-s {serial} push \"{localPath}\" /data/local/tmp/frida-server");
            await RunAdbAsync($"-s {serial} shell chmod +x /data/local/tmp/frida-server");
            await RunAdbAsync($"-s {serial} shell \"nohup /data/local/tmp/frida-server &\"");
            await _adb.ForwardPortsAsync(serial, 27042, 27042);

            return await IsRunningAsync(serial);
        }
        catch
        {
            return false;
        }
    }

    private async Task<string?> GetServerBinaryNameAsync(string serial, string version)
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
            "arm64-v8a" => $"frida-server-{version}-android-arm64",
            "armeabi-v7a" => $"frida-server-{version}-android-arm",
            "x86" => $"frida-server-{version}-android-x86",
            "x86_64" => $"frida-server-{version}-android-x86_64",
            _ => null
        };
    }

    private async Task<string?> EnsureBinaryAsync(string name, string version)
    {
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FridaDesk", "frida-servers", version);
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, name);
        if (!File.Exists(path))
        {
            var url = $"https://github.com/frida/frida/releases/download/{version}/{name}.xz";
            using var stream = await _http.GetStreamAsync(url);
            using var xz = new XZStream(stream);
            using var file = File.Create(path);
            await xz.CopyToAsync(file);
        }
        return path;
    }

    private async Task RunAdbAsync(string args)
    {
        var run = _runner.Run("adb", args);
        await foreach (var _ in run.Output) { }
        await run.WaitForExitAsync();
    }

    private async Task<bool> IsRunningAsync(string serial)
    {
        var run = _runner.Run("adb", $"-s {serial} shell ps | grep frida-server");
        var found = false;
        await foreach (var line in run.Output)
        {
            if (!string.IsNullOrWhiteSpace(line.Line))
                found = true;
        }
        await run.WaitForExitAsync();
        return found;
    }
}

