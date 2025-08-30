using System.Text.Json.Serialization;

namespace Brocode.Security.Application.Models;

public record NpmProjectModel
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("version")]
    public required string Version { get; init; }

    [JsonPropertyName("dependencies")]
    public Dictionary<string, Version> Depependencies { get; init; } = [];
}