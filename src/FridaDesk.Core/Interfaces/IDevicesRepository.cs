using FridaDesk.Core.Models;
using FridaDesk.Core.Results;

namespace FridaDesk.Core.Interfaces;

public interface IDevicesRepository
{
    Task<Result<DeviceInfo?>> GetAsync(string serial);
    Task<Result<IEnumerable<DeviceInfo>>> GetAllAsync();
    Task<Result> SaveAsync(DeviceInfo device);
    Task<Result> DeleteAsync(string serial);
}
