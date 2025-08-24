using FridaDesk.Infrastructure.Entities;
using Microsoft.EntityFrameworkCore;

namespace FridaDesk.Infrastructure;

public class FridaDeskDbContext : DbContext
{
    public FridaDeskDbContext(DbContextOptions<FridaDeskDbContext> options) : base(options)
    {
    }

    public DbSet<ScriptEntity> Scripts => Set<ScriptEntity>();
    internal DbSet<FavoriteEntity> Favorites => Set<FavoriteEntity>();
    internal DbSet<RunRecordEntity> Runs => Set<RunRecordEntity>();
    internal DbSet<DeviceEntity> Devices => Set<DeviceEntity>();
}
