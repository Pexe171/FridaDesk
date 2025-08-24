using Avalonia.Controls;
using Avalonia.Input;
using FridaHub.App.ViewModels;

namespace FridaHub.App.Views;

public partial class MainView : UserControl
{
    public MainView()
    {
        InitializeComponent();
    }

    public MainView(MainViewModel viewModel) : this()
    {
        DataContext = viewModel;
    }

    private void OnKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyModifiers == KeyModifiers.Control && e.Key == Key.R && DataContext is MainViewModel vm)
        {
            vm.RefreshDevicesCommand.Execute(null);
            e.Handled = true;
            return;
        }

        if (e.KeyModifiers == KeyModifiers.Control && e.Key == Key.L && DataContext is MainViewModel vm2)
        {
            vm2.ClearConsoleCommand.Execute(null);
            e.Handled = true;
            return;
        }

        if (e.KeyModifiers == KeyModifiers.None && e.Key == Key.Oem2)
        {
            var tabs = this.FindControl<TabControl>("MainTabs");
            if (tabs?.SelectedContent is ScriptsView scriptsView)
            {
                var search = scriptsView.FindControl<TextBox>("SearchBox");
                search?.Focus();
                e.Handled = true;
            }
        }
    }
}
