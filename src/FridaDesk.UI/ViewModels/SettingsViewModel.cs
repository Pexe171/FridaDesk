// Autor: Pexe (Instagram: David.devloli)
using System.Collections.ObjectModel;

namespace FridaDesk.UI.ViewModels;

public class SettingsViewModel
{
    public string AdbPath { get; set; } = "/usr/bin/adb";
    public string FridaPath { get; set; } = "/usr/bin/frida";
    public ObservableCollection<string> Themes { get; } = new() { "Dark", "Light", "System" };
    public string SelectedTheme { get; set; } = "System";
    public bool ShowElevatedTargets { get; set; } = true;
    public bool EnableJailbreakFeature { get; set; } = false;
}
