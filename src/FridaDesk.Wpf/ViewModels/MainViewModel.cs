using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace FridaDesk.Wpf.ViewModels;

// Autor: Pexe (instagram David.devloli)
public partial class MainViewModel : ObservableObject
{
    public DevicesViewModel DevicesViewModel { get; }

    [ObservableProperty]
    private ObservableObject currentViewModel;

    public ObservableCollection<string> ConsoleLines { get; } = new();

    public MainViewModel(DevicesViewModel devicesViewModel)
    {
        DevicesViewModel = devicesViewModel;
        currentViewModel = devicesViewModel;
    }

    [RelayCommand]
    private void ShowDevices() => CurrentViewModel = DevicesViewModel;
}
