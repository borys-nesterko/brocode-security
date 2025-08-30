using Brocode.Security.Core.Enums;

namespace Brocode.Security.Application.Models;

public record GetVulnerabilitiesQuery
{
    public Guid Id { get; init; }

    public required Ecosystem Ecosystem { get; init; }

    public required string FileContent { get; init; }
}