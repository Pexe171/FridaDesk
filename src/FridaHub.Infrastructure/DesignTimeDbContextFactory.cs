using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace FridaHub.Infrastructure;

public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<FridaHubDbContext>
{
    public FridaHubDbContext CreateDbContext(string[] args)
    {
        var baseDir = OperatingSystem.IsWindows()
            ? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        var appDir = Path.Combine(baseDir, "FridaHub");
        Directory.CreateDirectory(appDir);
        var dbPath = Path.Combine(appDir, "FridaHub.db");

        var options = new DbContextOptionsBuilder<FridaHubDbContext>()
            .UseSqlite($"Data Source={dbPath}")
            .Options;

        return new FridaHubDbContext(options);
    }
}
