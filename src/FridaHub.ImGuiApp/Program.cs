using System;

namespace FridaHub.ImGuiApp;

// Autor: Pexe (instagram David.devloli)
class Program
{
    static void Main(string[] args)
    {
        var provider = ServiceConfigurator.Configure();
        using var window = new MainWindow(provider);
        window.Run();
        if (provider is IDisposable d)
            d.Dispose();
    }
}
