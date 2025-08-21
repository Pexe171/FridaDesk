using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;
using FridaHub.Core.Models;

namespace FridaHub.Infrastructure.Entities;

internal class DeviceEntity
{
    [Key]
    public string Serial { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public bool IsEmulator { get; set; }
    public DevicePlatform Platform { get; set; }
    public string PropsJson { get; set; } = "{}";
    public DateTime LastSeenUtc { get; set; }

    [NotMapped]
    public Dictionary<string, string> Props
    {
        get => JsonSerializer.Deserialize<Dictionary<string, string>>(PropsJson) ?? new();
        set => PropsJson = JsonSerializer.Serialize(value);
    }
}
