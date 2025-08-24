// Autor: Pexe (Instagram: David.devloli)
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using FridaDesk.UI.ViewModels;

namespace FridaDesk.UI.Views;

public partial class DevicesView : UserControl
{
    public DevicesView()
    {
        InitializeComponent();
        DataContext = new DevicesViewModel();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
