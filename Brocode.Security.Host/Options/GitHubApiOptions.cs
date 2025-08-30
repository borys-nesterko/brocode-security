namespace Brocode.Security.Host.Options;

public record GitHubApiOptions
{
    public const string SectionName = "GitHubApi";
    public required string BaseUrl { get; init; }
    public required string AuthorizationToken { get; init; }
    public int TimeoutInSeconds { get; init; } = 10;
}