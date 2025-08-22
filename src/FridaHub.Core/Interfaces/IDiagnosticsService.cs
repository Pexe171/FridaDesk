using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using FridaHub.Core.Models;

namespace FridaHub.Core.Interfaces;

public interface IDiagnosticsService
{
    string? LastError { get; }
    ObservableCollection<string> LastCommands { get; }
    TimeSpan? LastAttachTime { get; }
    TimeSpan? LastSpawnTime { get; }
    ObservableCollection<DeviceInfo> LastDevices { get; }

    void RecordError(string message);
    void RecordCommand(string command);
    void RecordAttachTime(TimeSpan duration);
    void RecordSpawnTime(TimeSpan duration);
    void RecordDevices(IEnumerable<DeviceInfo> devices);
    string ExportReport(string directory, bool markdown);
}
