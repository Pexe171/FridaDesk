// Autor: Pexe (Instagram: David.devloli)
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using FridaDesk.UI.ViewModels;

namespace FridaDesk.UI.Views;

public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
        DataContext = new SettingsViewModel();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
