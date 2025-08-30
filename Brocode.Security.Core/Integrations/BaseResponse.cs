namespace Brocode.Security.Core.Integrations;

public class BaseResponse
{
    public bool IsSuccess { get; init; }

    public string? ErrorMessage { get; init; }
}