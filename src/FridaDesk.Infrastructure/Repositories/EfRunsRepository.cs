using FridaDesk.Core.Interfaces;
using FridaDesk.Core.Models;
using FridaDesk.Core.Results;
using FridaDesk.Infrastructure.Entities;
using Microsoft.EntityFrameworkCore;

namespace FridaDesk.Infrastructure.Repositories;

public class EfRunsRepository : IRunsRepository
{
    private readonly FridaDeskDbContext _db;

    public EfRunsRepository(FridaDeskDbContext db) => _db = db;

    public async Task<Result<RunRecord>> GetAsync(Guid id)
    {
        var entity = await _db.Runs.FindAsync(id);
        return entity is null
            ? Result<RunRecord>.Failure("Execução não encontrada")
            : Result<RunRecord>.Success(ToModel(entity));
    }

    public async Task<Result<IEnumerable<RunRecord>>> SearchAsync(string query)
    {
        var entities = await _db.Runs
            .Where(r => r.User.Contains(query) || r.Target.Contains(query))
            .ToListAsync();
        return Result<IEnumerable<RunRecord>>.Success(entities.Select(ToModel));
    }

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
            _db.Runs.Update(ToEntity(record));
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
        var entity = await _db.Runs.FindAsync(id);
        if (entity is null) return Result.Failure("Execução não encontrada");
        _db.Runs.Remove(entity);
        await _db.SaveChangesAsync();
        return Result.Success();
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

    private static RunRecordEntity ToEntity(RunRecord m) => new()
    {
        Id = m.Id,
        ScriptId = m.ScriptId,
        User = m.User,
        DeviceSerial = m.DeviceSerial,
        Target = m.Target,
        Mode = m.Mode,
        Status = m.Status,
        StartedAtUtc = m.StartedAtUtc,
        EndedAtUtc = m.EndedAtUtc,
        LogPath = m.LogPath
    };
}
