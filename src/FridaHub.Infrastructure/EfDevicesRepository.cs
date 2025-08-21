using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Core.Results;
using Microsoft.EntityFrameworkCore;

namespace FridaHub.Infrastructure;

public class EfDevicesRepository : IDevicesRepository
{
    private readonly FridaHubDbContext _db;

    public EfDevicesRepository(FridaHubDbContext db) => _db = db;

    public async Task<Result<DeviceInfo?>> GetAsync(string serial)
    {
        try
        {
            var entity = await _db.Devices.FindAsync(serial);
            return Result<DeviceInfo?>.Success(entity is null ? null : ToModel(entity));
        }
        catch (Exception ex)
        {
            return Result<DeviceInfo?>.Failure(ex.Message);
        }
    }

    public async Task<Result<IEnumerable<DeviceInfo>>> GetAllAsync()
    {
        try
        {
            var items = await _db.Devices.ToListAsync();
            return Result<IEnumerable<DeviceInfo>>.Success(items.Select(ToModel));
        }
        catch (Exception ex)
        {
            return Result<IEnumerable<DeviceInfo>>.Failure(ex.Message);
        }
    }

    public async Task<Result> SaveAsync(DeviceInfo device)
    {
        try
        {
            var entity = await _db.Devices.FindAsync(device.Serial);
            if (entity is null)
            {
                _db.Devices.Add(ToEntity(device));
            }
            else
            {
                UpdateEntity(entity, device);
            }
            await _db.SaveChangesAsync();
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    public async Task<Result> DeleteAsync(string serial)
    {
        try
        {
            var entity = await _db.Devices.FindAsync(serial);
            if (entity is null) return Result.Failure("Not found");
            _db.Devices.Remove(entity);
            await _db.SaveChangesAsync();
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    private static DeviceInfo ToModel(DeviceEntity e) => new()
    {
        Serial = e.Serial,
        Model = e.Model,
        IsEmulator = e.IsEmulator,
        Platform = e.Platform,
        Props = e.Props,
        LastSeenUtc = e.LastSeenUtc
    };

    private static DeviceEntity ToEntity(DeviceInfo d) => new()
    {
        Serial = d.Serial,
        Model = d.Model,
        IsEmulator = d.IsEmulator,
        Platform = d.Platform,
        Props = d.Props,
        LastSeenUtc = d.LastSeenUtc
    };

    private static void UpdateEntity(DeviceEntity e, DeviceInfo d)
    {
        e.Model = d.Model;
        e.IsEmulator = d.IsEmulator;
        e.Platform = d.Platform;
        e.Props = d.Props;
        e.LastSeenUtc = d.LastSeenUtc;
    }
}

