using FridaHub.Core.Models;
using FridaHub.Core.Results;

namespace FridaHub.Core.Backends;

public interface IAdbBackend
{
    Task<Result> StartServerAsync();
    Task<Result<IEnumerable<DeviceInfo>>> ListDevicesAsync();
    Task<Result<Dictionary<string, string>>> GetPropsAsync(string serial);
    Task<Result> ForwardPortsAsync(string serial, int localPort, int remotePort);
}
