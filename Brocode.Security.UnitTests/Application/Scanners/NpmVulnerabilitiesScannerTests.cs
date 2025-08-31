using Xunit;
using NSubstitute;
using Brocode.Security.Application.Scanners.Npm;
using Brocode.Security.Core.Integrations.GitHub;
using Microsoft.Extensions.Logging;
using Brocode.Security.Core.Models;
using Brocode.Security.Core.Enums;

namespace Brocode.Security.UnitTests.Application.Scanners
{
    public class NpmVulnerabilitiesScannerTests
    {
        private readonly NpmVulnerabilitiesScanner _scanner;
        private readonly IGitHubApiClient _gitHubApiClientMock;

        public NpmVulnerabilitiesScannerTests()
        {
            var loggerMock = Substitute.For<ILogger<NpmVulnerabilitiesScanner>>();
            _gitHubApiClientMock = Substitute.For<IGitHubApiClient>();
            _scanner = new NpmVulnerabilitiesScanner(_gitHubApiClientMock, loggerMock);
        }

        [Fact]
        public async Task ScanAsync_WithNoVulnerabilities_ReturnsEmptyList()
        {
            // Arrange
            var query = ScanPackagesQuery.Create(
                Guid.NewGuid(),
                Ecosystem.Npm,
                "{\"name\": \"My Application\",\"version\": \"1.0.0\",\"dependencies\": {\"underscore\": \"1.3.1\"}}");

            _gitHubApiClientMock.GetVulnerabilitiesAsync(query.Ecosystem.ToString(), "underscore", Arg.Any<CancellationToken>())
                .Returns(new GitHubResponse
                {
                    Data = new()
                    {
                        SecurityVulnerabilities = new()
                        {
                            Nodes = Array.Empty<SecurityVulnerability>()
                        }
                    }
                });

            // Act
            var result = await _scanner.ScanAsync(query, CancellationToken.None);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(result.Id, query.Id);
            Assert.True(result.IsSuccess);
            Assert.Empty(result.VulnerablePackages);
        }

        [Fact]
        public async Task ScanAsync_WithVulnerabilities_ReturnsVulnerablePackages()
        {
            // Arrange
            var query = ScanPackagesQuery.Create(
                Guid.NewGuid(),
                Ecosystem.Npm,
                "{ \"name\": \"My Application\", \"version\": \"1.0.0\", \"dependencies\": { \"deep-override\": \"1.0.1\", \"express\": \"4.17.1\" } }");

            _gitHubApiClientMock.GetVulnerabilitiesAsync(Ecosystem.Npm.ToString(), "deep-override", Arg.Any<CancellationToken>())
                .Returns(new GitHubResponse
                {
                    Data = new()
                    {
                        SecurityVulnerabilities = new()
                        {
                            Nodes =
                            [
                                new SecurityVulnerability
                                {
                                    Package = new Package { Name = "deep-override", Ecosystem = "NPM" },
                                    VulnerableVersionRange = "<1.0.2",
                                    FirstPatchedVersion = new FirstPatchedVersion { Identifier = "1.0.2" },
                                    Advisory = new Advisory { Summary = "Sample vulnerability in deep-override" },
                                    Severity = "HIGH"
                                }
                            ]
                        }
                    }
                });

            _gitHubApiClientMock.GetVulnerabilitiesAsync(Ecosystem.Npm.ToString(), "express", Arg.Any<CancellationToken>())
                .Returns(new GitHubResponse
                {
                    Data = new()
                    {
                        SecurityVulnerabilities = new()
                        {
                            Nodes =
                            [
                                new SecurityVulnerability
                                {
                                    Package = new Package { Name = "express", Ecosystem = "NPM" },
                                    VulnerableVersionRange = "<4.1.2",
                                    FirstPatchedVersion = new FirstPatchedVersion { Identifier = "4.1.2" },
                                    Advisory = new Advisory { Summary = "Sample vulnerability in express" },
                                    Severity = "MODERATE"
                                }
                            ]
                        }
                    }
                });

            // Act
            var result = await _scanner.ScanAsync(query, CancellationToken.None);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(result.Id, query.Id);
            Assert.True(result.IsSuccess);
            Assert.Single(result.VulnerablePackages);
            Assert.Equal("deep-override", result.VulnerablePackages[0].Name);
            Assert.Equal("1.0.1", result.VulnerablePackages[0].Version);
            Assert.Equal(Severity.High, result.VulnerablePackages[0].Severity);
            Assert.Equal("1.0.2", result.VulnerablePackages[0].FixedInVersion);
            Assert.Equal("Sample vulnerability in deep-override", result.VulnerablePackages[0].Summary);
        }
    }
}