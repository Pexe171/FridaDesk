using System.Windows;

namespace FridaDesk.Wpf.Views;

// Autor: Pexe (instagram David.devloli)
public partial class AboutDialog : Window
{
    public AboutDialog()
    {
        InitializeComponent();
    }

    private void OnCloseClicked(object sender, RoutedEventArgs e)
        => Close();
}
