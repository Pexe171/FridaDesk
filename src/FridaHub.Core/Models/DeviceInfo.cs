using System.ComponentModel;

namespace FridaHub.Core.Models;

public enum DevicePlatform
{
    Android,
    IOS,
    Unknown
}

public enum FridaStatus
{
    NotInstalled,
    Installing,
    Ready,
    Error
}

public class DeviceInfo : INotifyPropertyChanged
{
    public string Serial { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public bool IsEmulator { get; set; }
    public DevicePlatform Platform { get; set; }
    public Dictionary<string, string> Props { get; set; } = new();
    public DateTime LastSeenUtc { get; set; }

    private FridaStatus status = FridaStatus.NotInstalled;
    public FridaStatus Status
    {
        get => status;
        set
        {
            if (status != value)
            {
                status = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Status)));
            }
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}
