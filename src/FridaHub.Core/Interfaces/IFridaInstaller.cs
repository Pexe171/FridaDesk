using FridaHub.Core.Results;

namespace FridaHub.Core.Interfaces;

public interface IFridaInstaller
{
    Task<Result> InstallAsync(string serial);
}
