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
    public SettingsViewModel Settings { get; }

    [ObservableProperty]
    private ObservableCollection<string> logs = new();

    public MainViewModel(DevicesViewModel devices, ScriptsViewModel scripts, RunViewModel run, SettingsViewModel settings)
    {
        Devices = devices;
        Scripts = scripts;
        Run = run;
        Settings = settings;

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
        AddLog("Dispositivos atualizados");
    }
}
