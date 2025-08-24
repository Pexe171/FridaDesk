using System.Collections.ObjectModel;
using System.Windows.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FridaDesk.Wpf.Views;

namespace FridaDesk.Wpf.ViewModels;

// Autor: Pexe (instagram David.devloli)
public partial class MainViewModel : ObservableObject
{
    public DevicesView DevicesView { get; }

    [ObservableProperty]
    private UserControl currentView;

    public ObservableCollection<string> ConsoleLines { get; } = new();

    public MainViewModel(DevicesView devicesView, DevicesViewModel devicesViewModel)
    {
        DevicesView = devicesView;
        DevicesView.DataContext = devicesViewModel;
        currentView = devicesView;
    }

    [RelayCommand]
    private void NavigateDevices() => CurrentView = DevicesView;
}
