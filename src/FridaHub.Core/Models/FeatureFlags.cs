namespace FridaHub.Core.Models;

/// <summary>
/// Conjunto simples de flags de funcionalidades.
/// </summary>
public class FeatureFlags
{
    public bool EnableJailbreakFeature { get; set; } = false;
    public bool EnableAdvancedProcessList { get; set; } = false;
}
