using System;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using FridaDesk.Wpf.Services;

namespace FridaDesk.Wpf;

// Autor: Pexe (instagram David.devloli)
public partial class App : Application
{
    public static IServiceProvider Services { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        Services = ServiceProviderFactory.Create();
        var window = Services.GetRequiredService<MainWindow>();
        window.Show();
    }
}
