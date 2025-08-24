using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using FridaHub.Core.Interfaces;

namespace FridaDesk.Wpf.ViewModels;

// Autor: Pexe (instagram David.devloli)
public partial class DevicesViewModel : ObservableObject
{
    private readonly IAdbBackend adbBackend;

    public ObservableCollection<string> Devices { get; } = new();

    public DevicesViewModel(IAdbBackend adbBackend)
    {
        this.adbBackend = adbBackend;
    }
}
