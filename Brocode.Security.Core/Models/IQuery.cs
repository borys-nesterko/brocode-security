namespace Brocode.Security.Core.Models;

public interface IQuery
{
    Guid Id { get; init; }

    DateTime InitiatedAt { get; init; }

    T UnwrapContent<T>();
}