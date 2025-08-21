using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Core.Results;
using Microsoft.EntityFrameworkCore;

namespace FridaHub.Infrastructure;

public class EfRunsRepository : IRunsRepository
{
    private readonly FridaHubDbContext _db;

    public EfRunsRepository(FridaHubDbContext db) => _db = db;

    public async Task<Result> AddAsync(RunRecord record)
    {
        try
        {
            _db.Runs.Add(ToEntity(record));
            await _db.SaveChangesAsync();
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    public async Task<Result> UpdateAsync(RunRecord record)
    {
        try
        {
            var entity = await _db.Runs.FindAsync(record.Id);
            if (entity is null) return Result.Failure("Not found");
            UpdateEntity(entity, record);
            await _db.SaveChangesAsync();
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    public async Task<Result> DeleteAsync(Guid id)
    {
        try
        {
            var entity = await _db.Runs.FindAsync(id);
            if (entity is null) return Result.Failure("Not found");
            _db.Runs.Remove(entity);
            await _db.SaveChangesAsync();
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    public async Task<Result<RunRecord>> GetAsync(Guid id)
    {
        try
        {
            var entity = await _db.Runs.FindAsync(id);
            return entity is null
                ? Result<RunRecord>.Failure("Not found")
                : Result<RunRecord>.Success(ToModel(entity));
        }
        catch (Exception ex)
        {
            return Result<RunRecord>.Failure(ex.Message);
        }
    }

    public async Task<Result<IEnumerable<RunRecord>>> SearchAsync(string query)
    {
        try
        {
            var items = await _db.Runs
                .Where(r => EF.Functions.Like(r.Target, $"%{query}%"))
                .ToListAsync();
            return Result<IEnumerable<RunRecord>>.Success(items.Select(ToModel));
        }
        catch (Exception ex)
        {
            return Result<IEnumerable<RunRecord>>.Failure(ex.Message);
        }
    }

    private static RunRecord ToModel(RunRecordEntity e) => new()
    {
        Id = e.Id,
        ScriptId = e.ScriptId,
        User = e.User,
        DeviceSerial = e.DeviceSerial,
        Target = e.Target,
        Mode = e.Mode,
        Status = e.Status,
        StartedAtUtc = e.StartedAtUtc,
        EndedAtUtc = e.EndedAtUtc,
        LogPath = e.LogPath
    };

    private static RunRecordEntity ToEntity(RunRecord r) => new()
    {
        Id = r.Id,
        ScriptId = r.ScriptId,
        User = r.User,
        DeviceSerial = r.DeviceSerial,
        Target = r.Target,
        Mode = r.Mode,
        Status = r.Status,
        StartedAtUtc = r.StartedAtUtc,
        EndedAtUtc = r.EndedAtUtc,
        LogPath = r.LogPath
    };

    private static void UpdateEntity(RunRecordEntity e, RunRecord r)
    {
        e.ScriptId = r.ScriptId;
        e.User = r.User;
        e.DeviceSerial = r.DeviceSerial;
        e.Target = r.Target;
        e.Mode = r.Mode;
        e.Status = r.Status;
        e.StartedAtUtc = r.StartedAtUtc;
        e.EndedAtUtc = r.EndedAtUtc;
        e.LogPath = r.LogPath;
    }
}

