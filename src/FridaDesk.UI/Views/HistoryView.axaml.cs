// Autor: Pexe (Instagram: David.devloli)
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using FridaDesk.UI.ViewModels;

namespace FridaDesk.UI.Views;

public partial class HistoryView : UserControl
{
    public HistoryView()
    {
        InitializeComponent();
        DataContext = new HistoryViewModel();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
