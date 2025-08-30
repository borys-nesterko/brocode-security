using Brocode.Security.Core.Abstractions;
using Brocode.Security.Core.Enums;

namespace Brocode.Security.Core.Models;

public record ScanPackagesQuery : IQuery
{
    public Guid Id { get; init; }

    public DateTime InitiatedAt { get; init; } = DateTime.UtcNow;

    public required Ecosystem Ecosystem { get; init; }

    public required string Content { get; init; }
}