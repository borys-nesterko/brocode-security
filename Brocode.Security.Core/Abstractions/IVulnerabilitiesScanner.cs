using Brocode.Security.Core.Models;

namespace Brocode.Security.Core.Abstractions;

public interface IVulnerabilitiesScanner                                                                                      
{
    Task<ScanPackagesResult> ScanAsync(ScanPackagesQuery query, CancellationToken cancellationToken = default);                                                                                                                                                       
}