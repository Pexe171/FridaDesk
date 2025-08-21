using FridaHub.Infrastructure;
using FridaHub.Processes;

namespace FridaHub.Processes.Tests;

public class ProcessRunnerTests
{
    [Fact]
    public async Task RunAsync_CapturaSaida()
    {
        var runner = new ProcessRunner();
        var run = runner.Run("dotnet", "--version");
        var linhas = new List<string>();
        await foreach (var line in run.Output)
            linhas.Add(line.Line);
        var exit = await run.WaitForExitAsync();
        Assert.Equal(0, exit);
        Assert.NotEmpty(linhas);
    }

    [Fact]
    public async Task JsonlLogSink_EscreveArquivo()
    {
        var id = Guid.NewGuid();
        var sink = new JsonlLogSink(id);
        sink.AppendLine("{\"msg\":\"ok\"}");
        await sink.FlushAsync();

        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".fridahub", "logs");
        var path = Path.Combine(folder, $"{id}.jsonl");

        Assert.True(File.Exists(path));
        var content = await File.ReadAllTextAsync(path);
        Assert.Contains("\"msg\":\"ok\"", content);
    }
}

