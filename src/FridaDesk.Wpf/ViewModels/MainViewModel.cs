using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
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

    [ObservableProperty]
    private string consoleText = string.Empty;

    [ObservableProperty]
    private bool showAuthorizedBanner = true;

    public MainViewModel(DevicesView devicesView, DevicesViewModel devicesViewModel)
    {
        DevicesView = devicesView;
        DevicesView.DataContext = devicesViewModel;
        currentView = devicesView;
        LoadMockConsole();
    }

    [RelayCommand]
    private void NavigateDevices() => CurrentView = DevicesView;

    [RelayCommand]
    private void ClearConsole()
    {
        ConsoleLines.Clear();
        ConsoleText = string.Empty;
    }

    [RelayCommand]
    private void CopyConsole() => Clipboard.SetText(ConsoleText);

    [RelayCommand]
    private void SaveConsole() => File.WriteAllText("console.txt", string.Empty);

    [RelayCommand]
    private void DismissBanner() => ShowAuthorizedBanner = false;

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

    private void LoadMockConsole()
    {
        for (int i = 0; i < 20; i++)
        {
            var ts = DateTime.Now.AddSeconds(-20 + i).ToString("HH:mm:ss");
            var line = $"[{ts}] Linha {i + 1}";
            ConsoleLines.Add(line);
        }
        ConsoleText = string.Join(Environment.NewLine, ConsoleLines);
    }
}
