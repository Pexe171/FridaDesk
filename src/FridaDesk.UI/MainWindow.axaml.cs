// Autor: Pexe (Instagram: David.devloli)
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using System.Windows.Input;
using FridaDesk.UI.Views;

namespace FridaDesk.UI;

public partial class MainWindow : Window
{
    private readonly UserControl _devices = new DevicesView();
    private readonly UserControl _scripts = new ScriptsView();
    private readonly UserControl _history = new HistoryView();
    private readonly UserControl _settings = new SettingsView();

    public ICommand FocusSearchCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand ClearConsoleCommand { get; }

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
        ContentHost.Content = _devices;

        FocusSearchCommand = new RelayCommand(() => TopBar.SearchBox?.Focus());
        RefreshCommand = new RelayCommand(() => { });
        ClearConsoleCommand = new RelayCommand(() => Console.Text = string.Empty);
    }

    private void OnDevices(object? sender, RoutedEventArgs e) => ContentHost.Content = _devices;
    private void OnScripts(object? sender, RoutedEventArgs e) => ContentHost.Content = _scripts;
    private void OnHistory(object? sender, RoutedEventArgs e) => ContentHost.Content = _history;
    private void OnSettings(object? sender, RoutedEventArgs e) => ContentHost.Content = _settings;

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
