using Brocode.Security.Core.Abstractions;
using Brocode.Security.Core.Enums;

namespace Brocode.Security.Core.Models;

public record ScanPackagesResult : IResult
{
    public required Guid Id { get; init; }

    public required DateTime CompletedAt { get; init; }

    public PackageSummary[] VulnerablePackages { get; init; } = [];

    public string? ErrorMessage { get; private set; }

    internal static ScanPackagesResult FromError(Guid id, string errorMessage)
        => new()
        {
            Id = id,
            CompletedAt = DateTime.UtcNow,
            ErrorMessage = errorMessage
        };
}

public record PackageSummary
{
    public required string Name { get; init; }

    public required string Version { get; init; }

    public required string Summary { get; init; }

    public Severity Severity { get; init; }

    public string? FixedInVersion { get; init; }
}