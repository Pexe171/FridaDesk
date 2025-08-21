using CommunityToolkit.Mvvm.ComponentModel;

namespace FridaHub.App.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    [ObservableProperty]
    private string? adbPath;
}
