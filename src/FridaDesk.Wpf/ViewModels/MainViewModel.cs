using System.Collections.ObjectModel;
using System.Windows.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FridaDesk.Wpf.Views;
using System.Windows;

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

    [RelayCommand]
    private void ClearConsole() => ConsoleLines.Clear();

    [RelayCommand]
    private void FocusSearch(TextBox? box)
    {
        box?.Focus();
        box?.SelectAll();
    }

    [RelayCommand]
    private void OpenAbout()
    {
        var dialog = new AboutDialog
        {
            Owner = Application.Current.MainWindow
        };
        dialog.ShowDialog();
    }
}
