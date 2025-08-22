using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;
using FridaHub.Core.Models;

namespace FridaHub.Infrastructure.Entities;

public class ScriptEntity
{
    public Guid Id { get; set; }
    public ScriptSource Source { get; set; }
    public string Author { get; set; } = string.Empty;
    public string Slug { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string TagsJson { get; set; } = "[]";
    public string PlatformsJson { get; set; } = "[]";
    public string Fingerprint { get; set; } = string.Empty;
    public int? Popularity { get; set; }

    [NotMapped]
    public List<string> Tags
    {
        get => JsonSerializer.Deserialize<List<string>>(TagsJson) ?? new();
        set => TagsJson = JsonSerializer.Serialize(value);
    }

    [NotMapped]
    public List<string> Platforms
    {
        get => JsonSerializer.Deserialize<List<string>>(PlatformsJson) ?? new();
        set => PlatformsJson = JsonSerializer.Serialize(value);
    }
}
