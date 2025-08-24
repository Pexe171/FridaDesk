using System.Threading.Tasks;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Results;

namespace FridaDesk.Wpf.Extensions;

// Autor: Pexe (instagram David.devloli)
public static class FridaInstallerExtensions
{
    public static Task<Result> EnsureAsync(this IFridaInstaller installer, string serial)
        => installer.InstallAsync(serial);
}
