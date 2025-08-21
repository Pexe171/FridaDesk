using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Core.Results;
using Microsoft.EntityFrameworkCore;

namespace FridaHub.Infrastructure;

public class EfScriptsRepository : IScriptsRepository
{
    private readonly FridaHubDbContext _db;

    public EfScriptsRepository(FridaHubDbContext db) => _db = db;

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
            var entity = await _db.Scripts.FindAsync(script.Id);
            if (entity is null) return Result.Failure("Not found");
            UpdateEntity(entity, script);
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
            var entity = await _db.Scripts.FindAsync(id);
            if (entity is null) return Result.Failure("Not found");
            _db.Scripts.Remove(entity);
            await _db.SaveChangesAsync();
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    public async Task<Result<ScriptRef>> GetAsync(Guid id)
    {
        try
        {
            var entity = await _db.Scripts.FindAsync(id);
            return entity is null
                ? Result<ScriptRef>.Failure("Not found")
                : Result<ScriptRef>.Success(ToModel(entity));
        }
        catch (Exception ex)
        {
            return Result<ScriptRef>.Failure(ex.Message);
        }
    }

    public async Task<Result<IEnumerable<ScriptRef>>> SearchAsync(string query)
    {
        try
        {
            var items = await _db.Scripts
                .Where(s => EF.Functions.Like(s.Title, $"%{query}%") || EF.Functions.Like(s.Summary, $"%{query}%"))
                .ToListAsync();
            return Result<IEnumerable<ScriptRef>>.Success(items.Select(ToModel));
        }
        catch (Exception ex)
        {
            return Result<IEnumerable<ScriptRef>>.Failure(ex.Message);
        }
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
        Popularity = e.Popularity
    };

    private static ScriptEntity ToEntity(ScriptRef s) => new()
    {
        Id = s.Id,
        Source = s.Source,
        Author = s.Author,
        Slug = s.Slug,
        Title = s.Title,
        Summary = s.Summary,
        Tags = s.Tags,
        Platforms = s.Platforms,
        Fingerprint = s.Fingerprint,
        Popularity = s.Popularity
    };

    private static void UpdateEntity(ScriptEntity e, ScriptRef s)
    {
        e.Source = s.Source;
        e.Author = s.Author;
        e.Slug = s.Slug;
        e.Title = s.Title;
        e.Summary = s.Summary;
        e.Tags = s.Tags;
        e.Platforms = s.Platforms;
        e.Fingerprint = s.Fingerprint;
        e.Popularity = s.Popularity;
    }
}

