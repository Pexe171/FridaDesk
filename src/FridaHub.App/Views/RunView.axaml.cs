using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.VisualTree;
using FridaHub.App.ViewModels;

namespace FridaHub.App.Views;

public partial class RunView : UserControl
{
    public RunView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    public RunView(RunViewModel viewModel) : this()
    {
        DataContext = viewModel;
    }

    private async void OnLoaded(object? sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        if (DataContext is RunViewModel vm && !vm.IsAuthorized)
        {
            var dialog = new AuthorizationDialog { DataContext = vm };
            if (VisualRoot is Window window)
            {
                await dialog.ShowDialog(window);
            }
        }
    }
}
