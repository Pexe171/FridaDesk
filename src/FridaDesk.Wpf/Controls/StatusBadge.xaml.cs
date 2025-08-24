using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FridaHub.Core.Models;

namespace FridaDesk.Wpf.Controls;

// Autor: Pexe (instagram David.devloli)
public partial class StatusBadge : UserControl
{
    public StatusBadge()
    {
        InitializeComponent();
        UpdateVisual();
    }

    public FridaStatus Status
    {
        get => (FridaStatus)GetValue(StatusProperty);
        set => SetValue(StatusProperty, value);
    }

    public static readonly DependencyProperty StatusProperty =
        DependencyProperty.Register(nameof(Status), typeof(FridaStatus), typeof(StatusBadge), new PropertyMetadata(FridaStatus.NotInstalled, OnStatusChanged));

    private static void OnStatusChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((StatusBadge)d).UpdateVisual();

    private void UpdateVisual()
    {
        string text;
        Brush brush;
        switch (Status)
        {
            case FridaStatus.Ready:
                text = "pronto";
                brush = Brushes.Green;
                break;
            case FridaStatus.Error:
                text = "erro";
                brush = Brushes.Red;
                break;
            case FridaStatus.Installing:
                text = "instalando";
                brush = Brushes.Gray;
                break;
            default:
                text = "não iniciado";
                brush = Brushes.Orange;
                break;
        }
        BadgeBorder.Background = brush;
        BadgeText.Text = text;
        ToolTip = text;
    }
}
