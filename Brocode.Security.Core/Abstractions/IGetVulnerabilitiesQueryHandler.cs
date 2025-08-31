using Brocode.Security.Application.Models;
using Brocode.Security.Core.Models;

namespace Brocode.Security.Core.Abstractions;

public interface IGetVulnerabilitiesQueryHandler
{
    /// <summary>
    /// Processes the GetVulnerabilitiesQuery to scan for known vulnerabilities in the provided package file content.
    /// </summary>
    /// <param name="query"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<ScanPackagesResult> ProcessQueryAsync(GetVulnerabilitiesQuery query, CancellationToken cancellationToken = default);
}   