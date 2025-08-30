using System.Net.Mime;
using System.Text;
using System.Text.Json;
using Brocode.Security.Core.Abstractions;
using Brocode.Security.Core.Models;

namespace Brocode.Security.Infrastructure.ApiClients;

public class GitHubApiClient(HttpClient httpClient) : IGitHubApiClient
{
    private const string Url = "/graphql";
    
    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public async Task<GitHubResponse> GetVulnerabilitiesAsync(string ecosystem, string packageName)
    {
        var requestBody = new
        {
            query = GetQuery(ecosystem, packageName)
        };

        using var payload = new StringContent(
            JsonSerializer.Serialize(requestBody),
            Encoding.UTF8,
            MediaTypeNames.Application.Json);

        using var response = await httpClient.PostAsync(Url, payload);
        var content = await response.Content.ReadAsStringAsync();

        return JsonSerializer.Deserialize<GitHubResponse>(content, jsonOptions)!;
    }

    private static string GetQuery(string ecosystem, string packageName) => $@"{{
        securityVulnerabilities(ecosystem: {ecosystem.ToUpper()}, first: 100, package: ""{packageName}"") {{
                nodes {{
                    severity
                    advisory {{
                        summary
                    }}
                    package {{
                        name
                        ecosystem
                    }}
                    vulnerableVersionRange
                    firstPatchedVersion {{
                        identifier
                    }}
                }}
            }}
        }}";
}