namespace Brocode.Security.Core.Models;

public record ScanPackagesResult : IResult
{
    public Guid Id { get; private set; }

    public DateTime CompletedAt { get;  private set; }

    public PackageSummary[] VulnerablePackages { get; private set; } = [];

    public bool IsSuccess => string.IsNullOrEmpty(ErrorMessage);

    public string? ErrorMessage { get; private set; }

    public static ScanPackagesResult Create(Guid id, PackageSummary[] vulnerablePackages) =>
        new()
        {
            Id = id,
            CompletedAt = DateTime.UtcNow,
            VulnerablePackages = vulnerablePackages
        };

    public static ScanPackagesResult FromError(Guid id, string errorMessage) =>
        new()
        {
            Id = id,
            CompletedAt = DateTime.UtcNow,
            ErrorMessage = errorMessage
        };
}