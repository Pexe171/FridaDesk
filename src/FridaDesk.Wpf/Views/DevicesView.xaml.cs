using System.Windows.Controls;
using Microsoft.Extensions.DependencyInjection;
using FridaDesk.Wpf.ViewModels;

namespace FridaDesk.Wpf.Views;

// Autor: Pexe (instagram David.devloli)
public partial class DevicesView : UserControl
{
    public DevicesView()
    {
        InitializeComponent();
        DataContext = App.Services.GetRequiredService<DevicesViewModel>();
    }
}
