// Autor: Pexe (Instagram: David.devloli)
using System;
using System.Collections.ObjectModel;
using FridaDesk.UI.Controls;

namespace FridaDesk.UI.ViewModels;

public class HistoryViewModel
{
    public ObservableCollection<HistoryItem> Runs { get; } = new()
    {
        new HistoryItem { Date = DateTime.Now.AddMinutes(-5), Script = "Dump UI", Device = "Pixel 5", Status = "Ok" },
        new HistoryItem { Date = DateTime.Now.AddMinutes(-30), Script = "Bypass SSL", Device = "Android Emulator", Status = "Erro" },
        new HistoryItem { Date = DateTime.Now.AddHours(-2), Script = "Hook Touch", Device = "iPhone 12", Status = "Running" },
        new HistoryItem { Date = DateTime.Now.AddHours(-5), Script = "Trace Calls", Device = "Pixel 5", Status = "Ok" },
        new HistoryItem { Date = DateTime.Now.AddHours(-8), Script = "List Classes", Device = "Android Emulator", Status = "Ok" },
        new HistoryItem { Date = DateTime.Now.AddDays(-1), Script = "Interno A", Device = "Pixel 5", Status = "Erro" }
    };
}

public class HistoryItem
{
    public DateTime Date { get; set; }
    public string Script { get; set; } = string.Empty;
    public string Device { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public Severity StatusSeverity => Status switch
    {
        "Ok" => Severity.Success,
        "Erro" => Severity.Error,
        "Running" => Severity.Warning,
        _ => Severity.Muted
    };
}
