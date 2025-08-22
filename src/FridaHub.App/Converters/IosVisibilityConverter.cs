using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace FridaHub.App.Converters;

public class IosVisibilityConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return string.Equals(value as string, "IOS", StringComparison.OrdinalIgnoreCase);
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}
