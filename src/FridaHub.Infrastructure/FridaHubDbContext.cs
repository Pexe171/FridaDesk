using FridaHub.Infrastructure.Entities;
using Microsoft.EntityFrameworkCore;

namespace FridaHub.Infrastructure;

public class FridaHubDbContext : DbContext
{
    public FridaHubDbContext(DbContextOptions<FridaHubDbContext> options) : base(options)
    {
    }

    public DbSet<ScriptEntity> Scripts => Set<ScriptEntity>();
    internal DbSet<FavoriteEntity> Favorites => Set<FavoriteEntity>();
    internal DbSet<RunRecordEntity> Runs => Set<RunRecordEntity>();
    internal DbSet<DeviceEntity> Devices => Set<DeviceEntity>();
}
