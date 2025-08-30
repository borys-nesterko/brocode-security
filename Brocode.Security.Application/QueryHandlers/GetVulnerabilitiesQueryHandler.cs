using Brocode.Security.Application.Models;
using Brocode.Security.Core.Abstractions;
using Brocode.Security.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Brocode.Security.Application.Services;

public class GetVulnerabilitiesQueryHandler(
    IServiceProvider serviceProvider,
    ILogger<GetVulnerabilitiesQueryHandler> logger) : IGetVulnerabilitiesQueryHandler
{
    public Task<ScanPackagesResult> ProcessQueryAsync(GetVulnerabilitiesQuery query, CancellationToken cancellationToken)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(query);
            var ecosystem = query.Ecosystem.ToString();

            var scanPipeline = serviceProvider.GetRequiredKeyedService<IVulnerabilitiesScanner>(ecosystem);

            if (scanPipeline is null)
            {
                throw new InvalidOperationException($"'{query.Ecosystem}' scan pipeline is not supported yet.");
            }

            return scanPipeline.ScanAsync(ScanPackagesQuery.Create(query.Id, query.Ecosystem, query.FileContent));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An error occurred while scanning for vulnerabilities. {Message}", ex.Message);

            return Task.FromResult(ScanPackagesResult.FromError(query.Id, ex.Message)); 
        }
    }
}