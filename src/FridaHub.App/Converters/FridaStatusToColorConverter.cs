using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using FridaHub.Core.Models;

namespace FridaHub.App.Converters;

public class FridaStatusToColorConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is FridaStatus status ? status switch
        {
            FridaStatus.Ready => Brushes.LightGreen,
            FridaStatus.Error => Brushes.LightCoral,
            FridaStatus.Installing => Brushes.LightGoldenrodYellow,
            _ => Brushes.Orange
        } : Brushes.Orange;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
