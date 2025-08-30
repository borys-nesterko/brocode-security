using Brocode.Security.Application.Scanners.Npm;
using Brocode.Security.Application.Services;
using Brocode.Security.Core.Abstractions;
using Brocode.Security.Core.Enums;
using Brocode.Security.Core.Integrations.GitHub;
using Brocode.Security.Host.Options;
using Brocode.Security.Infrastructure.ApiClients;

namespace Brocode.Security.Host.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddServices(this IServiceCollection services)
    {
        services.AddSingleton<IGetVulnerabilitiesQueryHandler, GetVulnerabilitiesQueryHandler>();
        services.AddKeyedSingleton<IVulnerabilitiesScanner, NpmVulnerabilitiesScanner>(Ecosystem.Npm.ToString());

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
            client.DefaultRequestHeaders.Add("User-Agent", "Brocode Security App");
        })
        .AddStandardResilienceHandler();

        return services;
    }
}