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
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
