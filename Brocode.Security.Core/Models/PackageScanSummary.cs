using Brocode.Security.Core.Enums;

namespace Brocode.Security.Core.Models;

public record PackageSummary
{
    public required string Name { get; init; }

    public required string Version { get; init; }

    public required string Summary { get; init; }

    public Severity Severity { get; init; }

    public string? FixedInVersion { get; init; }
}