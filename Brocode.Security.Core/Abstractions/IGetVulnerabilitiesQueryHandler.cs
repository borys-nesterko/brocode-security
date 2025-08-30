using Brocode.Security.Application.Models;
using Brocode.Security.Core.Models;

namespace Brocode.Security.Core.Abstractions;

public interface IGetVulnerabilitiesQueryHandler
{
    Task<ScanPackagesResult> ProcessQueryAsync(GetVulnerabilitiesQuery query, CancellationToken cancellationToken = default);
}   