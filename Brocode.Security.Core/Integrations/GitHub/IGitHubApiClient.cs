namespace Brocode.Security.Core.Integrations.GitHub;

public interface IGitHubApiClient
{
    Task<GitHubResponse> GetVulnerabilitiesAsync(string ecosystem, string packageName, CancellationToken cancellationToken = default);
}