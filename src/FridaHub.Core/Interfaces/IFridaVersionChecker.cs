using System.Threading;
using System.Threading.Tasks;

namespace FridaHub.Core.Interfaces;

public interface IFridaVersionChecker
{
    Task<string?> GetVersionAsync(CancellationToken cancellationToken = default);
}
