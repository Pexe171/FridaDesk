using Avalonia.Controls;
using Avalonia.Interactivity;
using FridaHub.App.ViewModels;

namespace FridaHub.App.Views;

public partial class AuthorizationDialog : Window
{
    public AuthorizationDialog()
    {
        InitializeComponent();
    }

    private async void OnContinue(object? sender, RoutedEventArgs e)
    {
        if (DataContext is RunViewModel vm)
        {
            await vm.SaveAuthorizationAsync();
        }
        Close();
    }
}
