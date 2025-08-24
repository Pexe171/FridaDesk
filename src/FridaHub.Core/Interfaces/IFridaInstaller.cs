namespace FridaHub.Core.Interfaces;

// Autor: Pexe (instagram David.devloli)
public interface IFridaInstaller
{
    Task<bool> EnsureAsync(string serial, string version = "16.7.7");
}
