using System;
using Microsoft.Extensions.DependencyInjection;
using FridaHub.Infrastructure;
using FridaHub.Processes;
using FridaHub.Core.Backends;
using FridaHub.App.ViewModels;
using FridaHub.App.Views;
using FridaHub.Codeshare;

namespace FridaHub.App;

public static class ServiceConfigurator
{
    public static IServiceProvider Configure()
    {
        var services = new ServiceCollection();

        services.AddFridaHubInfrastructure();
        services.AddScoped<CodeshareSeedLoader>();
        services.AddSingleton<ProcessRunner>();
        services.AddSingleton<IAdbBackend, AdbService>();
        services.AddSingleton<IFridaBackend, FridaService>();

        services.AddSingleton<MainViewModel>();
        services.AddSingleton<DevicesViewModel>();
        services.AddSingleton<ScriptsViewModel>();
        services.AddSingleton<RunViewModel>();
        services.AddSingleton<SettingsViewModel>();

        services.AddTransient<MainView>();
        services.AddTransient<DevicesView>();
        services.AddTransient<ScriptsView>();
        services.AddTransient<RunView>();
        services.AddTransient<SettingsView>();

        var provider = services.BuildServiceProvider();

        using (var scope = provider.CreateScope())
        {
            var seeder = scope.ServiceProvider.GetRequiredService<CodeshareSeedLoader>();
            seeder.LoadAsync().GetAwaiter().GetResult();
        }

        return provider;
    }
}
