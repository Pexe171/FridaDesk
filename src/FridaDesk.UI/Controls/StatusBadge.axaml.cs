// Autor: Pexe (Instagram: David.devloli)
using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.Media;

namespace FridaDesk.UI.Controls;

public partial class StatusBadge : UserControl
{
    public static readonly StyledProperty<Severity> SeverityProperty =
        AvaloniaProperty.Register<StatusBadge, Severity>(nameof(Severity), defaultValue: Severity.Muted);

    public Severity Severity
    {
        get => GetValue(SeverityProperty);
        set => SetValue(SeverityProperty, value);
    }

    public StatusBadge()
    {
        InitializeComponent();
        this.PropertyChanged += (_, e) =>
        {
            if (e.Property == SeverityProperty)
                UpdateBackground(Severity);
        };
    }

    private void UpdateBackground(Severity severity)
    {
        var border = this.FindControl<Border>("PART_Border");
        var brush = severity switch
        {
            Severity.Success => (IBrush?)Application.Current?.FindResource("BrushOk"),
            Severity.Warning => (IBrush?)Application.Current?.FindResource("BrushWarn"),
            Severity.Error => (IBrush?)Application.Current?.FindResource("BrushError"),
            _ => (IBrush?)Application.Current?.FindResource("BrushMuted")
        };
        border.Background = brush;
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
