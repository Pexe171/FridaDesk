using System;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Infrastructure;
using FridaHub.Core.Backends;
using Microsoft.Extensions.DependencyInjection;

namespace FridaHub.App.ViewModels;

public partial class RunViewModel : ObservableObject
{
    private readonly ISettingsService _settingsService;
    private readonly IFridaBackend _backend;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IFridaVersionChecker _versionChecker;
    private CancellationTokenSource? _cts;

    public RunViewModel(ISettingsService settingsService, IFridaBackend backend, IServiceScopeFactory scopeFactory, IFridaVersionChecker versionChecker)
    {
        _settingsService = settingsService;
        _backend = backend;
        _scopeFactory = scopeFactory;
        _versionChecker = versionChecker;

        var result = _settingsService.LoadAsync().GetAwaiter().GetResult();
        if (result.IsSuccess && result.Value is { } settings)
        {
            IsAuthorized = settings.AuthorizedUseAccepted;
        }
    }

    public ObservableCollection<DeviceInfo> Devices { get; } = new();

    public IEnumerable<string> Modes { get; } = ["Attach", "Spawn"];

    public IEnumerable<string> Selectors { get; } = ["-U", "-R"];

    [ObservableProperty]
    private ObservableCollection<ProcessLine> output = new();

    [ObservableProperty]
    private bool isAuthorized;

    [ObservableProperty]
    private bool isDrawerOpen;

    [ObservableProperty]
    private DeviceInfo? selectedDevice;

    [ObservableProperty]
    private string target = string.Empty;

    [ObservableProperty]
    private string mode = "Attach";

    [ObservableProperty]
    private string? script;

    [ObservableProperty]
    private string selector = "-U";

    [ObservableProperty]
    private string parameters = string.Empty;

    [ObservableProperty]
    private bool isRunning;

    public async Task SaveAuthorizationAsync()
    {
        var settings = _settingsService.Current ?? new Settings();
        settings.AuthorizedUseAccepted = IsAuthorized;
        await _settingsService.SaveAsync(settings);
    }

    [RelayCommand(CanExecute = nameof(CanRun))]
    private async Task RunAsync()
    {
        IsRunning = true;
        _cts = new CancellationTokenSource();
        Output.Clear();

        var parts = (Script ?? string.Empty).Split('/', 2, StringSplitOptions.RemoveEmptyEntries);
        var author = parts.Length > 1 ? parts[0] : "Pexe (instagram David.devloli)";
        var slug = parts.Length > 1 ? parts[1] : (parts.Length == 1 ? parts[0] : string.Empty);

        var expectedVersion = _settingsService.Current?.ExpectedFridaVersion;
        var localVersion = await _versionChecker.GetVersionAsync();
        if (!string.IsNullOrWhiteSpace(expectedVersion) &&
            !string.IsNullOrWhiteSpace(localVersion) &&
            expectedVersion != localVersion)
        {
            var warn = new ProcessLine(DateTime.UtcNow, true, $"Aviso: frida {localVersion} difere de {expectedVersion}");
            Output.Add(warn);
        }

        var runId = Guid.NewGuid();
        var logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".fridahub", "logs", $"{runId}.jsonl");
        var record = new RunRecord
        {
            Id = runId,
            ScriptId = Guid.Empty,
            User = "Pexe (instagram David.devloli)",
            DeviceSerial = SelectedDevice!.Serial,
            Target = Target,
            Mode = Mode == "Attach" ? RunMode.Attach : RunMode.Spawn,
            Status = RunStatus.Running,
            StartedAtUtc = DateTime.UtcNow,
            LogPath = logPath
        };

        using var scope = _scopeFactory.CreateScope();
        var runsRepo = scope.ServiceProvider.GetRequiredService<IRunsRepository>();
        var scriptsRepo = scope.ServiceProvider.GetRequiredService<IScriptsRepository>();
        ScriptRef? localScript = null;
        if (!string.IsNullOrWhiteSpace(slug))
        {
            var search = await scriptsRepo.SearchAsync(slug);
            if (search.IsSuccess)
                localScript = search.Value.FirstOrDefault(s => s.Source == ScriptSource.Internal && s.Slug == slug);
            if (localScript is not null)
                record.ScriptId = localScript.Id;
        }
        await runsRepo.AddAsync(record);

        var sink = new JsonlLogSink(runId);

        try
        {
            IAsyncEnumerable<ProcessLine> exec = localScript is null
                ? _backend.RunCodeshareAsync(author, slug, Target, Selector, _cts.Token)
                : _backend.RunLocalScriptAsync(localScript.FilePath, Target, Selector, _cts.Token);

            await foreach (var line in exec.WithCancellation(_cts.Token))
            {
                Output.Add(line);
                var json = JsonSerializer.Serialize(new
                {
                    timestampUtc = line.TimestampUtc,
                    origin = line.IsError ? "stderr" : "stdout",
                    text = line.Line
                });
                sink.AppendLine(json);
            }
            record.Status = RunStatus.Ok;
        }
        catch (OperationCanceledException)
        {
            record.Status = RunStatus.Cancelled;
        }
        catch (Win32Exception)
        {
            var msg = "frida não encontrado. Verifique a instalação.";
            var pl = new ProcessLine(DateTime.UtcNow, true, msg);
            Output.Add(pl);
            sink.AppendLine(JsonSerializer.Serialize(new { timestampUtc = pl.TimestampUtc, origin = "stderr", text = pl.Line }));
            record.Status = RunStatus.Error;
        }
        catch (Exception ex)
        {
            var pl = new ProcessLine(DateTime.UtcNow, true, ex.Message);
            Output.Add(pl);
            sink.AppendLine(JsonSerializer.Serialize(new { timestampUtc = pl.TimestampUtc, origin = "stderr", text = pl.Line }));
            record.Status = RunStatus.Error;
        }
        finally
        {
            record.EndedAtUtc = DateTime.UtcNow;
            await sink.FlushAsync();
            await runsRepo.UpdateAsync(record);
            IsRunning = false;
        }
    }

    private bool CanRun() => !IsRunning &&
                              SelectedDevice is not null &&
                              !string.IsNullOrWhiteSpace(Target) &&
                              !string.IsNullOrWhiteSpace(Script);

    [RelayCommand(CanExecute = nameof(IsRunning))]
    private void Stop()
    {
        _cts?.Cancel();
        IsRunning = false;
    }

    [RelayCommand]
    private void OpenDrawer() => IsDrawerOpen = true;

    [RelayCommand]
    private void CloseDrawer() => IsDrawerOpen = false;

    [RelayCommand]
    private void SavePreset()
    {
        // futuro
    }

    partial void OnSelectedDeviceChanged(DeviceInfo? value) => RunCommand.NotifyCanExecuteChanged();
    partial void OnTargetChanged(string value) => RunCommand.NotifyCanExecuteChanged();
    partial void OnScriptChanged(string? value) => RunCommand.NotifyCanExecuteChanged();

    partial void OnIsRunningChanged(bool value)
    {
        RunCommand.NotifyCanExecuteChanged();
        StopCommand.NotifyCanExecuteChanged();
    }
}
