using System.Collections.ObjectModel;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FridaHub.Core.Backends;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;

namespace FridaDesk.Wpf.ViewModels;

// Autor: Pexe (instagram David.devloli)
public partial class DevicesViewModel : ObservableObject
{
    private readonly IAdbBackend adbBackend;
    private readonly IFridaInstaller fridaInstaller;

    public ObservableCollection<DeviceInfo> Devices { get; } = new();

    public DevicesViewModel(IAdbBackend adbBackend, IFridaInstaller fridaInstaller)
    {
        this.adbBackend = adbBackend;
        this.fridaInstaller = fridaInstaller;
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        var result = await adbBackend.ListDevicesAsync();
        Devices.Clear();
        if (result.IsSuccess && result.Value != null)
        {
            foreach (var device in result.Value)
                Devices.Add(device);
        }
    }

    [RelayCommand]
    private async Task EnsureFridaAsync(DeviceInfo device)
    {
        device.Status = FridaStatus.Installing;
        var ok = await fridaInstaller.EnsureAsync(device.Serial);
        device.Status = ok ? FridaStatus.Ready : FridaStatus.Error;
    }

    [RelayCommand]
    private Task RunAsync(DeviceInfo device) => Task.CompletedTask;
}
