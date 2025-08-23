using Avalonia;
using System;

namespace FridaHub.App;

class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        var services = ServiceConfigurator.Configure();
        App.Services = services;
        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex) when (ex.Message.Contains("XOpenDisplay"))
        {
            Console.Error.WriteLine("Interface gráfica não disponível. Certifique-se de executar em um ambiente com servidor gráfico.");
            Console.Error.WriteLine(ex.Message);
        }
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
