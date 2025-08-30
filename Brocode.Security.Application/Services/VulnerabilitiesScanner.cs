using Brocode.Security.Core.Abstractions;
using Brocode.Security.Core.Models;
using Microsoft.Extensions.DependencyInjection;

namespace Brocode.Security.Application.Services;

public class VulnerabilitiesScanner(IServiceProvider  serviceProvider) : IVulnerabilitiesScanner
{
    public Task<ScanPackagesResult> ScanAsync(ScanPackagesQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var ecosystem = query.Ecosystem.ToString();

        var scanPipeline = serviceProvider.GetRequiredKeyedService<IScanPipeline>(ecosystem);

        if (scanPipeline is null)
        {
            throw new InvalidOperationException($"'{query.Ecosystem}' scan pipeline is not supported yet.");
        }

       return scanPipeline.ScanPacakagesAsync(query);
    }
}