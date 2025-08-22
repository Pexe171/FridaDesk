using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;

namespace FridaHub.App.ViewModels;

public partial class RunViewModel : ObservableObject
{
    private readonly ISettingsService _settingsService;
    private CancellationTokenSource? _cts;

    public RunViewModel(ISettingsService settingsService)
    {
        _settingsService = settingsService;

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
        try
        {
            await Task.Delay(1000, _cts.Token);
        }
        catch (TaskCanceledException)
        {
            // ignorado
        }
        finally
        {
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
