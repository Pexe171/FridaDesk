using System.Text.Json;
using System.Linq;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using FridaHub.Core.Models;

namespace FridaHub.Infrastructure;

public class FridaHubDbContext : DbContext
{
    internal DbSet<ScriptEntity> Scripts => Set<ScriptEntity>();
    internal DbSet<FavoriteEntity> Favorites => Set<FavoriteEntity>();
    internal DbSet<RunRecordEntity> Runs => Set<RunRecordEntity>();
    internal DbSet<DeviceEntity> Devices => Set<DeviceEntity>();

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            var basePath = Paths.GetDataFolder();
            Directory.CreateDirectory(basePath);
            var dbPath = Path.Combine(basePath, "FridaHub.db");
            optionsBuilder.UseSqlite($"Data Source={dbPath}");
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var listConverter = new ValueConverter<List<string>, string>(
            v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
            v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new());
        var listComparer = new ValueComparer<List<string>>(
            (l1, l2) => l1.SequenceEqual(l2),
            l => l.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
            l => l.ToList());

        var dictConverter = new ValueConverter<Dictionary<string, string>, string>(
            v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
            v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, (JsonSerializerOptions?)null) ?? new());
        var dictComparer = new ValueComparer<Dictionary<string, string>>(
            (d1, d2) => d1.SequenceEqual(d2),
            d => d.Aggregate(0, (a, v) => HashCode.Combine(a, v.Key.GetHashCode(), v.Value.GetHashCode())),
            d => d.ToDictionary(e => e.Key, e => e.Value));

        modelBuilder.Entity<ScriptEntity>(e =>
        {
            e.ToTable("Scripts");
            e.HasKey(x => x.Id);
            e.Property(x => x.Tags).HasConversion(listConverter).Metadata.SetValueComparer(listComparer);
            e.Property(x => x.Platforms).HasConversion(listConverter).Metadata.SetValueComparer(listComparer);
        });

        modelBuilder.Entity<FavoriteEntity>(e =>
        {
            e.ToTable("Favorites");
            e.HasKey(x => x.Id);
            e.Property(x => x.Labels).HasConversion(listConverter).Metadata.SetValueComparer(listComparer);
        });

        modelBuilder.Entity<RunRecordEntity>(e =>
        {
            e.ToTable("Runs");
            e.HasKey(x => x.Id);
        });

        modelBuilder.Entity<DeviceEntity>(e =>
        {
            e.ToTable("Devices");
            e.HasKey(x => x.Serial);
            e.Property(x => x.Props).HasConversion(dictConverter).Metadata.SetValueComparer(dictComparer);
        });
    }
}

internal class ScriptEntity
{
    public Guid Id { get; set; }
    public ScriptSource Source { get; set; }
    public string Author { get; set; } = string.Empty;
    public string Slug { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public List<string> Tags { get; set; } = new();
    public List<string> Platforms { get; set; } = new();
    public string Fingerprint { get; set; } = string.Empty;
    public int? Popularity { get; set; }
}

internal class FavoriteEntity
{
    public Guid Id { get; set; }
    public Guid ScriptId { get; set; }
    public List<string> Labels { get; set; } = new();
    public string? Notes { get; set; }
    public string? PinnedFingerprint { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}

internal class RunRecordEntity
{
    public Guid Id { get; set; }
    public Guid ScriptId { get; set; }
    public string User { get; set; } = string.Empty;
    public string DeviceSerial { get; set; } = string.Empty;
    public string Target { get; set; } = string.Empty;
    public RunMode Mode { get; set; }
    public RunStatus Status { get; set; }
    public DateTime? StartedAtUtc { get; set; }
    public DateTime? EndedAtUtc { get; set; }
    public string? LogPath { get; set; }
}

internal class DeviceEntity
{
    public string Serial { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public bool IsEmulator { get; set; }
    public DevicePlatform Platform { get; set; }
    public Dictionary<string, string> Props { get; set; } = new();
    public DateTime LastSeenUtc { get; set; }
}

