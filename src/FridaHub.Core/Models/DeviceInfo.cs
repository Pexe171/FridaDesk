namespace FridaHub.Core.Models;

public enum DevicePlatform
{
    Android,
    IOS,
    Unknown
}

public class DeviceInfo
{
    public string Serial { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public bool IsEmulator { get; set; }
    public DevicePlatform Platform { get; set; }
    public Dictionary<string, string> Props { get; set; } = new();
    public DateTime LastSeenUtc { get; set; }
}
