using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using FridaHub.Infrastructure;
using FridaHub.Processes;
using FridaHub.Core.Backends;
using FridaHub.Core.Interfaces;
using FridaHub.Codeshare;

namespace FridaHub.ImGuiApp;

// Autor: Pexe (instagram David.devloli)
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
        services.AddSingleton<IFridaVersionChecker, FridaVersionChecker>();
        services.AddSingleton<IFridaInstaller, FridaInstaller>();

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

