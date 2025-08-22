using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Collections.ObjectModel;

namespace FridaHub.App.ViewModels;

public partial class MainViewModel : ObservableObject
{
    public string Title => "FridaHub (Desktop)";

    public DevicesViewModel Devices { get; }
    public ScriptsViewModel Scripts { get; }
    public RunViewModel Run { get; }
    public HistoryViewModel History { get; }
    public SettingsViewModel Settings { get; }
    public DiagnosticsViewModel Diagnostics { get; }

    [ObservableProperty]
    private ObservableCollection<string> logs = new();

    public MainViewModel(DevicesViewModel devices, ScriptsViewModel scripts, RunViewModel run, HistoryViewModel history, SettingsViewModel settings, DiagnosticsViewModel diagnostics)
    {
        Devices = devices;
        Scripts = scripts;
        Run = run;
        History = history;
        Settings = settings;
        Diagnostics = diagnostics;

        AddLog("Aplicação iniciada");
    }

    public string ConsoleText => string.Join("\n", Logs);

    private void AddLog(string line)
    {
        Logs.Add(line);
        OnPropertyChanged(nameof(ConsoleText));
    }

    [RelayCommand]
    private void RefreshDevices()
    {
        Devices.RefreshCommand.Execute(null);
        AddLog("Dispositivos atualizados");
    }

    [RelayCommand]
    private void ClearConsole()
    {
        Logs.Clear();
        OnPropertyChanged(nameof(ConsoleText));
    }
}
