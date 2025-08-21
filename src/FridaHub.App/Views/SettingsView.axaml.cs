using Avalonia.Controls;
using FridaHub.App.ViewModels;

namespace FridaHub.App.Views;

public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
    }

    public SettingsView(SettingsViewModel viewModel) : this()
    {
        DataContext = viewModel;
    }
}
