// Autor: Pexe (Instagram: David.devloli)
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace FridaDesk.UI.Controls;

public partial class Card : UserControl
{
    public static readonly StyledProperty<object?> HeaderProperty =
        AvaloniaProperty.Register<Card, object?>(nameof(Header));

    public object? Header
    {
        get => GetValue(HeaderProperty);
        set => SetValue(HeaderProperty, value);
    }

    public Card()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
