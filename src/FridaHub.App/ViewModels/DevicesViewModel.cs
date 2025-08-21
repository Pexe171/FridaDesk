using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using FridaHub.Core.Models;

namespace FridaHub.App.ViewModels;

public partial class DevicesViewModel : ObservableObject
{
    [ObservableProperty]
    private ObservableCollection<DeviceInfo> devices = new();

    [ObservableProperty]
    private DeviceInfo? selectedDevice;
}
