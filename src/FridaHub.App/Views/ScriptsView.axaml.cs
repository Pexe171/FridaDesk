using Avalonia.Controls;
using FridaHub.App.ViewModels;

namespace FridaHub.App.Views;

public partial class ScriptsView : UserControl
{
    public ScriptsView()
    {
        InitializeComponent();
    }

    public ScriptsView(ScriptsViewModel viewModel) : this()
    {
        DataContext = viewModel;
    }
}
