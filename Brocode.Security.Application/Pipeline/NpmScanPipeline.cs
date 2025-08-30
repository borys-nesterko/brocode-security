using Microsoft.Extensions.Logging;
using Brocode.Security.Core.Abstractions;
using Brocode.Security.Application.Models;
using System.Text.Json;
using Brocode.Security.Core.Models;
using Brocode.Security.Core.Enums;

namespace Brocode.Security.Application.Pipeline;

public sealed class NpmScanPipeline(
    IGitHubApiClient apiClient,
    ILogger<NpmScanPipeline> logger) 
    : IScanPipeline
{
    public async Task<ScanPackagesResult> ScanPacakagesAsync(ScanPackagesQuery query)
    {
        byte[] data = Convert.FromBase64String(query.Content);
        string decodedContent = System.Text.Encoding.UTF8.GetString(data);

        var npmProjectModel = JsonSerializer.Deserialize<NpmProjectModel>(decodedContent);

        ArgumentNullException.ThrowIfNull(npmProjectModel);

        var tasks = npmProjectModel.Depependencies.Select(package =>
             apiClient.GetVulnerabilitiesAsync(query.Ecosystem.ToString(), package.Key)).ToArray();

        await Task.WhenAll(tasks);

        var vulnerablePackages = npmProjectModel.Depependencies.SelectMany((dependency, index) =>
            FindVulnerabilities(dependency.Key, dependency.Value, tasks[index].Result)).ToArray();

        return new ScanPackagesResult
        {
            Id = query.Id,
            CompletedAt = DateTime.UtcNow,
            VulnerablePackages = vulnerablePackages
        };
    }

    private IEnumerable<PackageSummary> FindVulnerabilities(string packageName, Version packageVersion, GitHubResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);

        if (response?.Data?.SecurityVulnerabilities?.Nodes is null)
        {
            yield break;
        }

        foreach (var vulnerability in response.Data.SecurityVulnerabilities.Nodes)
        {
            if (vulnerability.FirstPatchedVersion is null)
            {
                continue;
            }

            if (HasComplexVersionRange(vulnerability.VulnerableVersionRange))
            {
                // Skipping vulnerabilities in between of alfa, beta, rc versions for the sake of simplicity
                // Production ready solution should cover this case as well with more sofisticated logic
                continue;
            }
            
            if (IsVersionVulnerable(packageVersion, vulnerability.FirstPatchedVersion.Identifier))
            {
                logger.LogWarning("Package {Package} has a vulnerability: {Vulnerability}", packageName, vulnerability.Advisory?.Summary);

                yield return new PackageSummary
                {
                    Name = packageName,
                    Version = packageVersion.ToString(),
                    Summary = vulnerability.Advisory?.Summary ?? "No summary provided",
                    Severity = Enum.TryParse<Severity>(vulnerability.Severity, true, out var severity) ? severity : Severity.Unknown,
                    FixedInVersion = vulnerability.FirstPatchedVersion.Identifier
                };
            }
        }
    }

    private static bool HasComplexVersionRange(string? vulnerableVersionRange)
    {
        var parts = vulnerableVersionRange?.Split(',');

        return parts?.Length > 1 ?
            parts.Any(part =>
                part.Contains("alpha") ||
                part.Contains("beta") ||
                part.Contains("rc")) : false;
        
    }

    private static bool IsVersionVulnerable(Version packageVersion, string patchedVersion) =>
        Version.TryParse(patchedVersion.Split('-')[0], out var version) ?
            packageVersion <= version : false;
}