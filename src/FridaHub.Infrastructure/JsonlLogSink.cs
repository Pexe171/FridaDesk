using FridaHub.Core.Interfaces;
using FridaHub.Core.Utils;

namespace FridaHub.Infrastructure;

/// <summary>
/// Gravador de logs em formato JSON Lines.
/// </summary>
public class JsonlLogSink : ILogSink
{
    private readonly string _filePath;
    private readonly List<string> _buffer = new();

    public JsonlLogSink(Guid runId)
    {
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".fridahub", "logs");
        Directory.CreateDirectory(folder);
        _filePath = Path.Combine(folder, $"{runId}.jsonl");
    }

    public void AppendLine(string line) => _buffer.Add(LogSanitizer.Sanitize(line));

    public async Task FlushAsync()
    {
        await File.AppendAllLinesAsync(_filePath, _buffer);
        _buffer.Clear();
    }
}

