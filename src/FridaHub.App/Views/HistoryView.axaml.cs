using Avalonia.Controls;
using FridaHub.App.ViewModels;

namespace FridaHub.App.Views;

public partial class HistoryView : UserControl
{
    public HistoryView()
    {
        InitializeComponent();
    }

    public HistoryView(HistoryViewModel viewModel) : this()
    {
        DataContext = viewModel;
    }
}
