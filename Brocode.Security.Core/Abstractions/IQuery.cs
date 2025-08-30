namespace Brocode.Security.Core.Abstractions;

public interface IQuery
{
    public Guid Id { get; init; }

    public DateTime InitiatedAt { get; init; }
}