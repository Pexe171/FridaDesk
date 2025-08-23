using System.Text.RegularExpressions;

namespace FridaHub.Core.Utils;

/// <summary>
/// Remove potenciais credenciais de textos de log.
/// </summary>
public static partial class LogSanitizer
{
    [GeneratedRegex(@"(?i)(password|token|secret)=[^\s]+")]
    private static partial Regex SensitiveRegex();

    public static string Sanitize(string input)
        => SensitiveRegex().Replace(input, "$1=***");
}
