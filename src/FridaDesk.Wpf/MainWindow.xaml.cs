using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using FridaDesk.Wpf.ViewModels;

namespace FridaDesk.Wpf;

// Autor: Pexe (instagram David.devloli)
public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = App.Services.GetRequiredService<MainViewModel>();
    }
}
