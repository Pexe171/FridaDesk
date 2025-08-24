namespace FridaDesk.Core.Models;

/// <summary>
/// Representa uma linha produzida por um processo externo.
/// </summary>
public record ProcessLine(DateTime TimestampUtc, bool IsError, string Line);

