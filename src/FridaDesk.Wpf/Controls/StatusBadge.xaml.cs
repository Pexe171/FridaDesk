using System.Windows;
using System.Windows.Controls;

namespace FridaDesk.Wpf.Controls;

// Autor: Pexe (instagram David.devloli)
public partial class StatusBadge : UserControl
{
    public StatusBadge()
    {
        InitializeComponent();
    }

    public string Text
    {
        get => (string)GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    public static readonly DependencyProperty TextProperty =
        DependencyProperty.Register(nameof(Text), typeof(string), typeof(StatusBadge), new PropertyMetadata(string.Empty));
}
