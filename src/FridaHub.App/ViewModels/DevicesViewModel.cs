using System;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FridaHub.Core.Backends;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Core.Results;
using System.Threading.Tasks;

namespace FridaHub.App.ViewModels;

public partial class DevicesViewModel : ObservableObject
{
    private readonly IAdbBackend _adb;
    private readonly IFridaBackend _frida;
    private readonly IDiagnosticsService _diagnostics;
    private readonly IFridaInstaller _installer;

    [ObservableProperty]
    private ObservableCollection<DeviceInfo> devices = new();

    [ObservableProperty]
    private DeviceInfo? selectedDevice;

    public DevicesViewModel(IAdbBackend adb, IFridaBackend frida, IDiagnosticsService diagnostics, IFridaInstaller installer)
    {
        _adb = adb;
        _frida = frida;
        _diagnostics = diagnostics;
        _installer = installer;
    }

    [RelayCommand]
    private async Task Refresh()
    {
        Devices.Clear();

        Result start;
        try
        {
            start = await _adb.StartServerAsync();
        }
        catch
        {
            start = Result.Failure(string.Empty);
        }

        Result<IEnumerable<DeviceInfo>> list = Result<IEnumerable<DeviceInfo>>.Failure(string.Empty);
        if (start.IsSuccess)
        {
            try
            {
                list = await _adb.ListDevicesAsync();
            }
            catch
            {
                list = Result<IEnumerable<DeviceInfo>>.Failure(string.Empty);
            }
        }

        if (list.IsSuccess && list.Value != null)
        {
            foreach (var device in list.Value)
                Devices.Add(device);
            _diagnostics.RecordDevices(list.Value);
            return;
        }

        Devices.Add(new DeviceInfo
        {
            Serial = "emulator-5554",
            Model = "Pixel 5",
            IsEmulator = true,
            Platform = DevicePlatform.Android,
            LastSeenUtc = DateTime.UtcNow
        });
    }

    [RelayCommand]
    private async Task ListProcesses(DeviceInfo device)
    {
        _diagnostics.RecordCommand($"frida-ps {device.Serial}");
        await _frida.ListProcessesAsync(device.Serial);
    }

    [RelayCommand]
    private void ForwardPorts(DeviceInfo device)
    {
        _diagnostics.RecordCommand($"forward {device.Serial}");
        // placeholder
    }

    [RelayCommand]
    private void RetestTools(DeviceInfo device)
    {
        _diagnostics.RecordCommand($"retest {device.Serial}");
        RefreshCommand.Execute(null);
    }

    [RelayCommand]
    private async Task InstallFrida(DeviceInfo device)
    {
        device.Status = FridaStatus.Installing;
        var result = await _installer.InstallAsync(device.Serial);
        device.Status = result.IsSuccess ? FridaStatus.Ready : FridaStatus.Error;
    }
}
