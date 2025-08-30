namespace Brocode.Security.Core.Models;

public interface IResult
{
    Guid Id { get; }

    DateTime CompletedAt { get; }

    bool IsSuccess { get; }

    string? ErrorMessage { get; }
}