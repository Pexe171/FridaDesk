namespace FridaHub.Core.Models;

public enum ScriptSource
{
    Codeshare,
    Internal
}

public class ScriptRef
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
