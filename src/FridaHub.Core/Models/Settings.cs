namespace FridaHub.Core.Models;

public enum Theme
{
    Dark,
    Light,
    System
}

public class Settings
{
    public string? AdbPath { get; set; }
    public string? FridaPath { get; set; }
    public Theme Theme { get; set; } = Theme.System;
    public string LogsFolder { get; set; } = string.Empty;
    public string ResourcesFolder { get; set; } = string.Empty;
    public bool ShowElevatedTargets { get; set; }
    public bool EnableJailbreakFeature { get; set; } = false;
}
