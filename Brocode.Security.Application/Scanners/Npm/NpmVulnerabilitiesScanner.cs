using Microsoft.Extensions.Logging;
using Brocode.Security.Core.Abstractions;
using Brocode.Security.Core.Models;
using Brocode.Security.Core.Enums;
using Brocode.Security.Core.Models.Npm;
using Brocode.Security.Core.Integrations.GitHub;

namespace Brocode.Security.Application.Scanners.Npm;

public sealed class NpmVulnerabilitiesScanner(
    IGitHubApiClient apiClient,
    ILogger<NpmVulnerabilitiesScanner> logger) 
    : IVulnerabilitiesScanner 
{
    public async Task<ScanPackagesResult> ScanAsync(ScanPackagesQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var npmPackageModel = query.UnwrapContent<NpmProjectModel>();

        var tasks = npmPackageModel.Dependencies.Select(package =>
            apiClient.GetVulnerabilitiesAsync(query.Ecosystem.ToString(), package.Key, cancellationToken))
            .ToArray();

        await Task.WhenAll(tasks);

        if (tasks.Any(t => t.Result.IsSuccess == false))
        {
            var errorMessage = tasks.First(t => t.Result.IsSuccess == false).Result.ErrorMessage;
            logger.LogError("One or more errors occurred while fetching vulnerabilities: {ErrorMessage}", errorMessage);

            return ScanPackagesResult.FromError(query.Id, errorMessage!);
        };

        var vulnerablePackages = npmPackageModel.Dependencies.SelectMany((dependency, index) =>
            FindVulnerabilities(dependency.Key, dependency.Value, tasks[index].Result)).ToArray();

        return ScanPackagesResult.Create(query.Id, vulnerablePackages);
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
            if (vulnerability.FirstPatchedVersion?.Identifier is null)
            {
                continue;
            }

            // Skipping vulnerabilities in between of alfa, beta, rc versions for the sake of simplicity
            // Production ready solution should cover this case as well with more sofisticated logic
            if (HasComplexVersionRange(vulnerability.VulnerableVersionRange))
            {
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