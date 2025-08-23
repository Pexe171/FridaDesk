using System;
using System.Globalization;
using Avalonia.Data.Converters;
using FridaHub.Core.Models;

namespace FridaHub.App.Converters;

public class IosVisibilityConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is DevicePlatform platform
            ? platform == DevicePlatform.IOS
            : string.Equals(value?.ToString(), "IOS", StringComparison.OrdinalIgnoreCase);
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}
