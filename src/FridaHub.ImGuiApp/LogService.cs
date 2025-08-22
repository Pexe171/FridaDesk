using System.Collections.Generic;

namespace FridaHub.ImGuiApp;

// Autor: Pexe (instagram David.devloli)
public static class LogService
{
    private static readonly List<string> _lines = new();
    private static readonly object _lock = new();

    public static IEnumerable<string> Lines
    {
        get
        {
            lock (_lock)
            {
                return _lines.ToArray();
            }
        }
    }

    public static void Append(string msg)
    {
        lock (_lock)
        {
            _lines.Add(msg);
        }
    }
}
