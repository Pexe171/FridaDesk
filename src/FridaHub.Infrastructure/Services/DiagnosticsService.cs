using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;

namespace FridaHub.Infrastructure.Services;

public class DiagnosticsService : IDiagnosticsService
{
    public string? LastError { get; private set; }
    public ObservableCollection<string> LastCommands { get; } = new();
    public TimeSpan? LastAttachTime { get; private set; }
    public TimeSpan? LastSpawnTime { get; private set; }
    public ObservableCollection<DeviceInfo> LastDevices { get; } = new();

    public void RecordError(string message) => LastError = message;
    public void RecordCommand(string command) => LastCommands.Add(command);
    public void RecordAttachTime(TimeSpan duration) => LastAttachTime = duration;
    public void RecordSpawnTime(TimeSpan duration) => LastSpawnTime = duration;
    public void RecordDevices(IEnumerable<DeviceInfo> devices)
    {
        LastDevices.Clear();
        foreach (var d in devices)
            LastDevices.Add(d);
    }

    public string ExportReport(string directory, bool markdown)
    {
        Directory.CreateDirectory(directory);
        var ext = markdown ? "md" : "txt";
        var file = Path.Combine(directory, $"diagnostico-{DateTime.UtcNow:yyyyMMddHHmmss}.{ext}");
        var sb = new StringBuilder();
        if (markdown)
        {
            sb.AppendLine("# Relatório de Diagnóstico");
            sb.AppendLine();
            sb.AppendLine("## Último erro");
            sb.AppendLine(LastError ?? "Nenhum");
            sb.AppendLine();
            sb.AppendLine("## Últimos comandos");
            foreach (var c in LastCommands)
                sb.AppendLine($"- {c}");
            sb.AppendLine();
            sb.AppendLine("## Tempo de attach");
            sb.AppendLine(LastAttachTime?.ToString() ?? "N/A");
            sb.AppendLine();
            sb.AppendLine("## Tempo de spawn");
            sb.AppendLine(LastSpawnTime?.ToString() ?? "N/A");
            sb.AppendLine();
            sb.AppendLine("## Últimos devices");
            foreach (var d in LastDevices)
                sb.AppendLine($"- {d.Serial}");
        }
        else
        {
            sb.AppendLine("Relatório de Diagnóstico");
            sb.AppendLine($"Último erro: {LastError ?? "Nenhum"}");
            sb.AppendLine("Últimos comandos:");
            foreach (var c in LastCommands)
                sb.AppendLine(c);
            sb.AppendLine($"Tempo de attach: {LastAttachTime?.ToString() ?? "N/A"}");
            sb.AppendLine($"Tempo de spawn: {LastSpawnTime?.ToString() ?? "N/A"}");
            sb.AppendLine("Últimos devices:");
            foreach (var d in LastDevices)
                sb.AppendLine(d.Serial);
        }
        File.WriteAllText(file, sb.ToString());
        return file;
    }
}
