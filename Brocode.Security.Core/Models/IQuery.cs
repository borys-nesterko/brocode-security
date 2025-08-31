namespace Brocode.Security.Core.Models;

public interface IQuery
{
    Guid Id { get; init; }

    DateTime InitiatedAt { get; init; }

    bool TryParseContent<T>(out T? model);
}