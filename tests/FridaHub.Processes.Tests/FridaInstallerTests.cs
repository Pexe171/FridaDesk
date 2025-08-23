using FridaHub.Core.Backends;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Core.Results;
using FridaHub.Processes;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace FridaHub.Processes.Tests;

public class FridaInstallerTests
{
    private class FakeAdb : IAdbBackend
    {
        private readonly string _abi;
        public FakeAdb(string abi) => _abi = abi;
        public Task<Result> StartServerAsync() => Task.FromResult(Result.Success());
        public Task<Result<IEnumerable<DeviceInfo>>> ListDevicesAsync() => Task.FromResult(Result<IEnumerable<DeviceInfo>>.Success(Enumerable.Empty<DeviceInfo>()));
        public Task<Result<Dictionary<string, string>>> GetPropsAsync(string serial) => Task.FromResult(Result<Dictionary<string, string>>.Success(new()));
        public Task<Result<string>> GetPropAsync(string serial, string key) => Task.FromResult(Result<string>.Success(_abi));
        public Task<Result> ForwardPortsAsync(string serial, int localPort, int remotePort) => Task.FromResult(Result.Success());
    }

    [Theory]
    [InlineData("arm64-v8a", "frida-server-16.7.7-android-arm64")]
    [InlineData("armeabi-v7a", "frida-server-16.7.7-android-arm")]
    [InlineData("x86", "frida-server-16.7.7-android-x86")]
    [InlineData("x86_64", "frida-server-16.7.7-android-x86_64")]
    public async Task EscolheBinarioCorreto(string abi, string esperado)
    {
        var adb = new FakeAdb(abi);
        var installer = new FridaInstaller(adb, new ProcessRunner(new FakeSettingsService()), new HttpClient(new HttpClientHandler()));
        var result = await installer.GetServerBinaryNameAsync("abc");
        Assert.True(result.IsSuccess);
        Assert.Equal(esperado, result.Value);
    }
}

