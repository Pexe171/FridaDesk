using System;
using System.Globalization;
using Avalonia.Data.Converters;
using FridaHub.Core.Models;

namespace FridaHub.App.Converters;

public class FridaStatusTextConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is FridaStatus status ? status switch
        {
            FridaStatus.Ready => "Pronto (frida-server ativo)",
            FridaStatus.Error => "Erro",
            FridaStatus.Installing => "Instalando...",
            _ => "Instalar frida-server"
        } : "Instalar frida-server";
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
