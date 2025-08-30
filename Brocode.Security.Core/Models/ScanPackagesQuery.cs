using System.Text.Json;
using Brocode.Security.Core.Enums;

namespace Brocode.Security.Core.Models;

public record ScanPackagesQuery : IQuery
{
    private string _fileContent;

    public Guid Id { get; init; }

    public DateTime InitiatedAt { get; init; } = DateTime.UtcNow;

    public required Ecosystem Ecosystem { get; init; }

    public static ScanPackagesQuery Create(Guid id, Ecosystem ecosystem, string fileContent) =>
        new()
        {
            Id = Guid.NewGuid(),
            Ecosystem = ecosystem,
            _fileContent = fileContent
        };

    public T UnwrapContent<T>()
    {
        byte[] data = Convert.FromBase64String(_fileContent);
        string decodedContent = System.Text.Encoding.UTF8.GetString(data);

        return Ecosystem switch
        {
            Ecosystem.Npm => JsonSerializer.Deserialize<T>(decodedContent)
                ?? throw new InvalidOperationException("Failed to deserialize the file content."),
            _ => throw new NotSupportedException($"Ecosystem '{Ecosystem}' is not supported yet."),
        };
    }
}