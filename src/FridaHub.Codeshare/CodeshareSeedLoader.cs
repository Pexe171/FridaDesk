using System.Text.Json;
using FridaHub.Core.Models;
using FridaHub.Infrastructure;
using FridaHub.Infrastructure.Entities;
using Microsoft.EntityFrameworkCore;

namespace FridaHub.Codeshare;

public class CodeshareSeedLoader
{
    private readonly FridaHubDbContext _db;
    private readonly string _seedPath;

    public CodeshareSeedLoader(FridaHubDbContext db)
    {
        _db = db;
        _seedPath = Path.Combine(AppContext.BaseDirectory, "seed.json");
    }

    public async Task LoadAsync()
    {
        if (!File.Exists(_seedPath)) return;

        var json = await File.ReadAllTextAsync(_seedPath);
        var seeds = JsonSerializer.Deserialize<List<ScriptSeed>>(json);
        if (seeds is null) return;

        foreach (var seed in seeds)
        {
            if (await _db.Scripts.AnyAsync(s => s.Slug == seed.Slug))
                continue;

            _db.Scripts.Add(new ScriptEntity
            {
                Id = Guid.NewGuid(),
                Source = ScriptSource.Codeshare,
                Author = seed.Author,
                Slug = seed.Slug,
                Title = seed.Title,
                Tags = seed.Tags,
                Platforms = seed.Platforms
            });
        }

        await _db.SaveChangesAsync();
    }

    private class ScriptSeed
    {
        public string Source { get; set; } = string.Empty;
        public string Author { get; set; } = string.Empty;
        public string Slug { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public List<string> Tags { get; set; } = new();
        public List<string> Platforms { get; set; } = new();
    }
}
