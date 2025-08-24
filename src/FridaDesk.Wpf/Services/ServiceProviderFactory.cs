using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using FridaHub.Infrastructure;
using FridaHub.Processes;
using FridaHub.Codeshare;
using FridaHub.Core.Backends;
using FridaHub.Core.Interfaces;
using FridaDesk.Wpf.ViewModels;
using FridaDesk.Wpf.Views;

namespace FridaDesk.Wpf.Services;

// Autor: Pexe (instagram David.devloli)
public static class ServiceProviderFactory
{
    public static IServiceProvider Create()
    {
        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: true)
            .Build();

        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);

        services.AddFridaHubInfrastructure();
        services.AddScoped<CodeshareSeedLoader>();
        services.AddSingleton<ProcessRunner>();
        services.AddSingleton<IAdbBackend, AdbService>();
        services.AddSingleton<IFridaBackend, CliFridaBackend>();
        services.AddSingleton<IFridaVersionChecker, FridaVersionChecker>();
        services.AddSingleton<IFridaInstaller, FridaInstaller>();

        services.AddSingleton<MainViewModel>();
        services.AddSingleton<DevicesViewModel>();
        services.AddSingleton<DevicesView>();

        services.AddTransient<MainWindow>();

        var provider = services.BuildServiceProvider();

        using (var scope = provider.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<FridaHubDbContext>();
            context.Database.Migrate();

            var seeder = scope.ServiceProvider.GetRequiredService<CodeshareSeedLoader>();
            seeder.LoadAsync().GetAwaiter().GetResult();
        }

        return provider;
    }
}
