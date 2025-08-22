using FridaHub.App.ViewModels;
using FridaHub.Core.Backends;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Core.Results;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using Xunit;

namespace FridaHub.Processes.Tests;

public class DevicesViewModelTests
{
    private class DummyAdb : IAdbBackend
    {
        public Task<Result> StartServerAsync() => Task.FromResult(Result.Success());
        public Task<Result<IEnumerable<DeviceInfo>>> ListDevicesAsync() => Task.FromResult(Result<IEnumerable<DeviceInfo>>.Success(Enumerable.Empty<DeviceInfo>()));
        public Task<Result<Dictionary<string, string>>> GetPropsAsync(string serial) => Task.FromResult(Result<Dictionary<string, string>>.Success(new()));
        public Task<Result<string>> GetPropAsync(string serial, string key) => Task.FromResult(Result<string>.Success(""));
        public Task<Result> ForwardPortsAsync(string serial, int localPort, int remotePort) => Task.FromResult(Result.Success());
    }

    private class DummyFrida : IFridaBackend
    {
        public IAsyncEnumerable<ProcessLine> RunCodeshareAsync(string author, string slug, string package, string? selector = null, CancellationToken cancellationToken = default)
        {
            return Empty();
            static async IAsyncEnumerable<ProcessLine> Empty()
            {
                yield break;
            }
        }
        public IAsyncEnumerable<ProcessLine> RunLocalScriptAsync(string scriptPath, string package, string? selector = null, CancellationToken cancellationToken = default)
        {
            return Empty();
            static async IAsyncEnumerable<ProcessLine> Empty()
            {
                yield break;
            }
        }
        public Task<Result<IEnumerable<string>>> ListProcessesAsync(string? deviceSerial = null, CancellationToken cancellationToken = default) => Task.FromResult(Result<IEnumerable<string>>.Success(Enumerable.Empty<string>()));
    }

    private class DummyDiag : IDiagnosticsService
    {
        public string? LastError => null;
        public ObservableCollection<string> LastCommands { get; } = new();
        public TimeSpan? LastAttachTime => null;
        public TimeSpan? LastSpawnTime => null;
        public ObservableCollection<DeviceInfo> LastDevices { get; } = new();
        public void RecordError(string message) { }
        public void RecordCommand(string command) { }
        public void RecordAttachTime(TimeSpan duration) { }
        public void RecordSpawnTime(TimeSpan duration) { }
        public void RecordDevices(IEnumerable<DeviceInfo> devices) { }
        public string ExportReport(string directory, bool markdown) => string.Empty;
    }

    private class FakeInstaller : IFridaInstaller
    {
        private readonly bool _ok;
        public FakeInstaller(bool ok) => _ok = ok;
        public Task<Result> InstallAsync(string serial) => Task.FromResult(_ok ? Result.Success() : Result.Failure("erro"));
    }

    [Fact]
    public async Task StatusAtualizaAposInstalacao()
    {
        var device = new DeviceInfo { Serial = "123" };
        var vm = new DevicesViewModel(new DummyAdb(), new DummyFrida(), new DummyDiag(), new FakeInstaller(true));
        await vm.InstallFridaCommand.ExecuteAsync(device);
        Assert.Equal(FridaStatus.Ready, device.Status);
    }

    [Fact]
    public async Task StatusErroQuandoFalha()
    {
        var device = new DeviceInfo { Serial = "123" };
        var vm = new DevicesViewModel(new DummyAdb(), new DummyFrida(), new DummyDiag(), new FakeInstaller(false));
        await vm.InstallFridaCommand.ExecuteAsync(device);
        Assert.Equal(FridaStatus.Error, device.Status);
    }
}
