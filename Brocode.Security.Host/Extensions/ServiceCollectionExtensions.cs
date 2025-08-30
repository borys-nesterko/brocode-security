using Brocode.Security.Application.Models;
using Brocode.Security.Application.Pipeline;
using Brocode.Security.Application.Services;
using Brocode.Security.Core.Abstractions;
using Brocode.Security.Host.Options;
using Brocode.Security.Infrastructure.ApiClients;
using Microsoft.Extensions.Configuration;

namespace Brocode.Security.Host.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddServices(this IServiceCollection services)
    {
        // Register the pipeline and stages
        services.AddSingleton<IVulnerabilitiesScanner, VulnerabilitiesScanner>();
        services.AddKeyedSingleton<IScanPipeline, NpmScanPipeline>("Npm");

        return services;
    }

    public static IServiceCollection AddGitHubApiClient(this IServiceCollection services, IConfigurationSection section)
    {
        var options = section.Get<GitHubApiOptions>();

        ArgumentNullException.ThrowIfNull(options, "GitHubApiOptions is not configured properly.");

        services.AddHttpClient<IGitHubApiClient, GitHubApiClient>(client =>
        {
            client.BaseAddress = new Uri(options.BaseUrl);
            client.Timeout = TimeSpan.FromSeconds(options.TimeoutInSeconds);
            client.DefaultRequestHeaders.Add("Authorization", options.AuthorizationToken);
            client.DefaultRequestHeaders.Add("User-Agent", "BrocodeSecurityApp");
        })
        .AddStandardResilienceHandler();

        return services;
    }
}