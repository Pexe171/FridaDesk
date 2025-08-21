using CommunityToolkit.Mvvm.ComponentModel;

namespace FridaHub.App.ViewModels;

public partial class MainViewModel : ObservableObject
{
    public string Title => "FridaHub (Desktop)";

    public DevicesViewModel Devices { get; }
    public ScriptsViewModel Scripts { get; }
    public RunViewModel Run { get; }
    public SettingsViewModel Settings { get; }

    public MainViewModel(DevicesViewModel devices, ScriptsViewModel scripts, RunViewModel run, SettingsViewModel settings)
    {
        Devices = devices;
        Scripts = scripts;
        Run = run;
        Settings = settings;
    }
}
