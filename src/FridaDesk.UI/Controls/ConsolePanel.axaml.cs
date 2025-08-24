// Autor: Pexe (Instagram: David.devloli)
using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;

namespace FridaDesk.UI.Controls;

public partial class ConsolePanel : UserControl
{
    public static readonly StyledProperty<string> TextProperty =
        AvaloniaProperty.Register<ConsolePanel, string>(nameof(Text), "");

    public string Text
    {
        get => GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    public ConsolePanel()
    {
        InitializeComponent();
        this.PropertyChanged += (_, e) =>
        {
            if (e.Property == TextProperty)
                ConsoleBox.Text = Text;
        };
    }

    private void OnCopy(object? sender, RoutedEventArgs e)
    {
        var tb = ConsoleBox;
        TopLevel.GetTopLevel(this)?.Clipboard?.SetTextAsync(tb.Text ?? string.Empty);
    }

    private void OnClear(object? sender, RoutedEventArgs e)
    {
        Text = string.Empty;
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
