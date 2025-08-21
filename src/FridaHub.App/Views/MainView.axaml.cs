using Avalonia.Controls;
using FridaHub.App.ViewModels;

namespace FridaHub.App.Views;

public partial class MainView : Window
{
    public MainView()
    {
        InitializeComponent();
    }

    public MainView(MainViewModel viewModel) : this()
    {
        DataContext = viewModel;
    }
}
