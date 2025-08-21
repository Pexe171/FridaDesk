using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;

namespace FridaHub.Infrastructure.Entities;

internal class FavoriteEntity
{
    public Guid Id { get; set; }
    public Guid ScriptId { get; set; }
    public string LabelsJson { get; set; } = "[]";
    public string? Notes { get; set; }
    public string? PinnedFingerprint { get; set; }
    public DateTime CreatedAtUtc { get; set; }

    [NotMapped]
    public List<string> Labels
    {
        get => JsonSerializer.Deserialize<List<string>>(LabelsJson) ?? new();
        set => LabelsJson = JsonSerializer.Serialize(value);
    }
}
