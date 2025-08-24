// Autor: Pexe (instagram David.devloli)
using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using FridaHub.Core.Models;

namespace FridaDesk.Wpf.Converters;

public class IosVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is DevicePlatform platform && platform == DevicePlatform.IOS ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}
