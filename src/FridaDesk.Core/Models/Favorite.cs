namespace FridaDesk.Core.Models;

public class Favorite
{
    public Guid Id { get; set; }
    public Guid ScriptId { get; set; }
    public List<string> Labels { get; set; } = new();
    public string? Notes { get; set; }
    public string? PinnedFingerprint { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
