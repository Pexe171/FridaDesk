// Autor: Pexe (Instagram: David.devloli)
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using FridaDesk.UI.ViewModels;

namespace FridaDesk.UI.Views;

public partial class ScriptsView : UserControl
{
    public ScriptsView()
    {
        InitializeComponent();
        DataContext = new ScriptsViewModel();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
