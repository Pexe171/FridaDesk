using FridaHub.Core.Models;

namespace FridaHub.Infrastructure.Entities;

internal class RunRecordEntity
{
    public Guid Id { get; set; }
    public Guid ScriptId { get; set; }
    public string User { get; set; } = string.Empty;
    public string DeviceSerial { get; set; } = string.Empty;
    public string Target { get; set; } = string.Empty;
    public RunMode Mode { get; set; }
    public RunStatus Status { get; set; }
    public DateTime? StartedAtUtc { get; set; }
    public DateTime? EndedAtUtc { get; set; }
    public string? LogPath { get; set; }
}
