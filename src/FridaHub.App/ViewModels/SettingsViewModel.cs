using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Processes;

namespace FridaHub.App.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly ISettingsService _settingsService;
    private readonly ProcessRunner _runner;

    public SettingsViewModel(ISettingsService settingsService, ProcessRunner runner)
    {
        _settingsService = settingsService;
        _runner = runner;
        LoadAsync().GetAwaiter().GetResult();
    }

    public Theme[] Themes { get; } = Enum.GetValues<Theme>();

    [ObservableProperty]
    private string? adbPath;

    [ObservableProperty]
    private string? fridaPath;

    [ObservableProperty]
    private string logsFolder = string.Empty;

    [ObservableProperty]
    private string resourcesFolder = string.Empty;

    [ObservableProperty]
    private Theme theme;

    [ObservableProperty]
    private bool showElevatedTargets;

    [ObservableProperty]
    private string? expectedFridaVersion;

    [ObservableProperty]
    private string toolsTestResult = string.Empty;

    private async Task LoadAsync()
    {
        var result = await _settingsService.LoadAsync();
        if (result.IsSuccess && result.Value is not null)
        {
            var s = result.Value;
            AdbPath = s.AdbPath;
            FridaPath = s.FridaPath;
            LogsFolder = s.LogsFolder;
            ResourcesFolder = s.ResourcesFolder;
            Theme = s.Theme;
            ShowElevatedTargets = s.ShowElevatedTargets;
            ExpectedFridaVersion = s.ExpectedFridaVersion;
        }
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        var settings = new Settings
        {
            AdbPath = AdbPath,
            FridaPath = FridaPath,
            LogsFolder = LogsFolder,
            ResourcesFolder = ResourcesFolder,
            Theme = Theme,
            ShowElevatedTargets = ShowElevatedTargets,
            ExpectedFridaVersion = ExpectedFridaVersion,
            AuthorizedUseAccepted = _settingsService.Current?.AuthorizedUseAccepted ?? false
        };
        await _settingsService.SaveAsync(settings);
    }

    [RelayCommand]
    private async Task TestToolsAsync()
    {
        var sb = new StringBuilder();
        sb.AppendLine(await RunVersion(AdbPath, "version"));
        sb.AppendLine(await RunVersion(FridaPath, "--version"));
        ToolsTestResult = sb.ToString().Trim();
    }

    private async Task<string> RunVersion(string? path, string args)
    {
        if (string.IsNullOrWhiteSpace(path))
            return "Caminho não configurado";

        try
        {
            var resolved = Resolve(path);
            var run = _runner.Run(resolved, args);
            var output = new List<string>();
            await foreach (var line in run.Output)
                output.Add(line.Line);
            var exit = await run.WaitForExitAsync();
            return exit == 0
                ? string.Join('\n', output)
                : $"Erro ({exit})";
        }
        catch (Exception ex)
        {
            return $"Erro: {ex.Message}";
        }
    }

    private string Resolve(string path)
        => Path.IsPathRooted(path) ? path : Path.Combine(ResourcesFolder, path);
}
