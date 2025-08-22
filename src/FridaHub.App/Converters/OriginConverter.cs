using System;
using Avalonia.Data.Converters;
using System.Globalization;

namespace FridaHub.App.Converters;

public class OriginConverter : IValueConverter
{
    public static readonly OriginConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is bool b ? (b ? "stderr" : "stdout") : "stdout";

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
