using System;
using System.IO;

namespace FridaHub.Infrastructure;

internal static class Paths
{
    public static string GetDataFolder()
    {
        if (OperatingSystem.IsWindows())
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FridaHub");
        }

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(home, ".local", "share", "FridaHub");
    }
}

