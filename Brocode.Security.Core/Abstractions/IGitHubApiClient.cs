using Brocode.Security.Core.Models;

namespace Brocode.Security.Core.Abstractions;

public interface IGitHubApiClient
{
    Task<GitHubResponse> GetVulnerabilitiesAsync(string ecosystem, string packageName);
}