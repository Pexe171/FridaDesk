// Autor: Pexe (Instagram: David.devloli)
using System.Collections.ObjectModel;
using FridaDesk.UI.Controls;

namespace FridaDesk.UI.ViewModels;

public class DevicesViewModel
{
    public ObservableCollection<DeviceItem> Devices { get; } = new()
    {
        new DeviceItem { Serial = "ABC123", Model = "Pixel 5", IsEmulator = false, Status = "Pronto" },
        new DeviceItem { Serial = "EMUL01", Model = "Android Emulator", IsEmulator = true, Status = "Não Instalado" },
        new DeviceItem { Serial = "IOS999", Model = "iPhone 12", IsEmulator = false, Status = "Erro" }
    };
}

public class DeviceItem
{
    public string Serial { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public bool IsEmulator { get; set; }
    public string Status { get; set; } = string.Empty;

    public string EmulatorLabel => IsEmulator ? "Sim" : "Não";
    public Severity EmulatorSeverity => IsEmulator ? Severity.Success : Severity.Muted;
    public Severity StatusSeverity => Status switch
    {
        "Pronto" => Severity.Success,
        "Erro" => Severity.Error,
        _ => Severity.Muted
    };
}
