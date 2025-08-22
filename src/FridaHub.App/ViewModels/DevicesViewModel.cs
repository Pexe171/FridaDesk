using System;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FridaHub.Core.Backends;
using FridaHub.Core.Models;
using FridaHub.Core.Results;
using System.Threading.Tasks;

namespace FridaHub.App.ViewModels;

public partial class DevicesViewModel : ObservableObject
{
    private readonly IAdbBackend _adb;

    [ObservableProperty]
    private ObservableCollection<DeviceInfo> devices = new();

    [ObservableProperty]
    private DeviceInfo? selectedDevice;

    public DevicesViewModel(IAdbBackend adb)
    {
        _adb = adb;
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
}
