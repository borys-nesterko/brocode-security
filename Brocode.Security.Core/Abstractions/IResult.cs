namespace Brocode.Security.Core.Abstractions;

public interface IResult
{
    public Guid Id { get; init; }

    public DateTime CompletedAt { get; init; }

    public string? ErrorMessage { get; }
}