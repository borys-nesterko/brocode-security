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

    public bool TryParseContent<T>(out T? model)
    {
        try
        {
            switch (Ecosystem)
            {
                case Ecosystem.Npm:
                    model = JsonSerializer.Deserialize<T>(_fileContent);
                    return true;
                default:
                    model = default!;
                    return false;
            }
        }
        catch (JsonException)
        {
            model = default;
            return false;
        }

    }
}