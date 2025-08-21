using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Core.Results;
using FridaHub.Infrastructure.Entities;
using Microsoft.EntityFrameworkCore;

namespace FridaHub.Infrastructure.Repositories;

public class EfDevicesRepository : IDevicesRepository
{
    private readonly FridaHubDbContext _db;

    public EfDevicesRepository(FridaHubDbContext db) => _db = db;

    public async Task<Result<DeviceInfo?>> GetAsync(string serial)
    {
        var entity = await _db.Devices.FindAsync(serial);
        return Result<DeviceInfo?>.Success(entity is null ? null : ToModel(entity));
    }

    public async Task<Result<IEnumerable<DeviceInfo>>> GetAllAsync()
    {
        var entities = await _db.Devices.ToListAsync();
        return Result<IEnumerable<DeviceInfo>>.Success(entities.Select(ToModel));
    }

    public async Task<Result> SaveAsync(DeviceInfo device)
    {
        try
        {
            var existing = await _db.Devices.FindAsync(device.Serial);
            if (existing is null)
            {
                _db.Devices.Add(ToEntity(device));
            }
            else
            {
                _db.Entry(existing).CurrentValues.SetValues(ToEntity(device));
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
        var entity = await _db.Devices.FindAsync(serial);
        if (entity is null)
            return Result.Success();
        _db.Devices.Remove(entity);
        await _db.SaveChangesAsync();
        return Result.Success();
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

    private static DeviceEntity ToEntity(DeviceInfo m) => new()
    {
        Serial = m.Serial,
        Model = m.Model,
        IsEmulator = m.IsEmulator,
        Platform = m.Platform,
        Props = m.Props,
        LastSeenUtc = m.LastSeenUtc
    };
}
