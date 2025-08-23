using Avalonia.Controls;
using FridaHub.App.ViewModels;

namespace FridaHub.App.Views;

public partial class RunView : UserControl
{
    public RunView()
    {
        InitializeComponent();
    }

    public RunView(RunViewModel viewModel) : this()
    {
        DataContext = viewModel;
    }

}
