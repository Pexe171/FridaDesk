using Avalonia.Controls;
using FridaHub.App.ViewModels;

namespace FridaHub.App.Views;

public partial class DevicesView : UserControl
{
    public DevicesView()
    {
        InitializeComponent();
    }

    public DevicesView(DevicesViewModel viewModel) : this()
    {
        DataContext = viewModel;
    }
}
