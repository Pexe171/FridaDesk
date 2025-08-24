// Autor: Pexe (Instagram: David.devloli)
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace FridaDesk.UI.Controls;

public partial class Toolbar : UserControl
{
    public static readonly StyledProperty<string> TitleProperty =
        AvaloniaProperty.Register<Toolbar, string>(nameof(Title), "");

    public static readonly StyledProperty<object?> ActionsProperty =
        AvaloniaProperty.Register<Toolbar, object?>(nameof(Actions));

    public string Title
    {
        get => GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    public object? Actions
    {
        get => GetValue(ActionsProperty);
        set => SetValue(ActionsProperty, value);
    }

    public Toolbar()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
