using System;
using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;

namespace FridaHub.App.ViewModels;

public partial class DiagnosticsViewModel : ObservableObject
{
    private readonly IDiagnosticsService _diagnostics;

    public DiagnosticsViewModel(IDiagnosticsService diagnostics)
    {
        _diagnostics = diagnostics;
    }

    public string? LastError => _diagnostics.LastError;
    public ObservableCollection<string> LastCommands => _diagnostics.LastCommands;
    public TimeSpan? LastAttachTime => _diagnostics.LastAttachTime;
    public TimeSpan? LastSpawnTime => _diagnostics.LastSpawnTime;
    public ObservableCollection<DeviceInfo> LastDevices => _diagnostics.LastDevices;

    [RelayCommand]
    private void ExportReport()
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".fridahub");
        _diagnostics.ExportReport(dir, true);
    }
}
