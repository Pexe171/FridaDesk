namespace FridaDesk.Core.Interfaces;

public interface ILogSink
{
    void AppendLine(string line);
    Task FlushAsync();
}
