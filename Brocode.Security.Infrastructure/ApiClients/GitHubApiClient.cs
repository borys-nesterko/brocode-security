using System.Net.Mime;
using System.Text;
using System.Text.Json;
using Brocode.Security.Core.Integrations.GitHub;

namespace Brocode.Security.Infrastructure.ApiClients;

public class GitHubApiClient(HttpClient httpClient) : IGitHubApiClient
{
    private const string Url = "/graphql";
    
    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public async Task<GitHubResponse> GetVulnerabilitiesAsync(string ecosystem, string packageName, CancellationToken cancellationToken)
    {
        var queryBuilder = new QueryBuilder()
            .WithEcosystem(ecosystem)
            .WithPackageName(packageName);

        using var payload = new StringContent(
            queryBuilder.Build(),
            Encoding.UTF8,
            MediaTypeNames.Application.Json);

        //Resilience policies can be added directly to HttpClient via Polly
        using var response = await httpClient.PostAsync(Url, payload, cancellationToken);

        if (response.IsSuccessStatusCode is false)
        {
            return new GitHubResponse
            {
                IsSuccess = false,
                ErrorMessage = $"GitHub API request failed with status code: {response.StatusCode}"
            };
        }
        var content = await response.Content.ReadAsStringAsync();

        return JsonSerializer.Deserialize<GitHubResponse>(content, jsonOptions)!;
    }
}