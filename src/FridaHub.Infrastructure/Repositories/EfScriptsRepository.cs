using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Core.Results;
using FridaHub.Infrastructure.Entities;
using Microsoft.EntityFrameworkCore;

namespace FridaHub.Infrastructure.Repositories;

public class EfScriptsRepository : IScriptsRepository
{
    private readonly FridaHubDbContext _db;

    public EfScriptsRepository(FridaHubDbContext db) => _db = db;

    public async Task<Result<ScriptRef>> GetAsync(Guid id)
    {
        var entity = await _db.Scripts.FindAsync(id);
        return entity is null
            ? Result<ScriptRef>.Failure("Script não encontrado")
            : Result<ScriptRef>.Success(ToModel(entity));
    }

    public async Task<Result<IEnumerable<ScriptRef>>> SearchAsync(string query)
    {
        var entities = await _db.Scripts
            .Where(s => s.Title.Contains(query) || s.Author.Contains(query) || s.Slug.Contains(query))
            .ToListAsync();
        return Result<IEnumerable<ScriptRef>>.Success(entities.Select(ToModel));
    }

    public async Task<Result> AddAsync(ScriptRef script)
    {
        try
        {
            _db.Scripts.Add(ToEntity(script));
            await _db.SaveChangesAsync();
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    public async Task<Result> UpdateAsync(ScriptRef script)
    {
        try
        {
            _db.Scripts.Update(ToEntity(script));
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
        var entity = await _db.Scripts.FindAsync(id);
        if (entity is null) return Result.Failure("Script não encontrado");
        _db.Scripts.Remove(entity);
        await _db.SaveChangesAsync();
        return Result.Success();
    }

    private static ScriptRef ToModel(ScriptEntity e) => new()
    {
        Id = e.Id,
        Source = e.Source,
        Author = e.Author,
        Slug = e.Slug,
        Title = e.Title,
        Summary = e.Summary,
        Tags = e.Tags,
        Platforms = e.Platforms,
        Fingerprint = e.Fingerprint,
        Popularity = e.Popularity,
        FilePath = e.FilePath
    };

    private static ScriptEntity ToEntity(ScriptRef m) => new()
    {
        Id = m.Id,
        Source = m.Source,
        Author = m.Author,
        Slug = m.Slug,
        Title = m.Title,
        Summary = m.Summary,
        Tags = m.Tags,
        Platforms = m.Platforms,
        Fingerprint = m.Fingerprint,
        Popularity = m.Popularity,
        FilePath = m.FilePath
    };
}
