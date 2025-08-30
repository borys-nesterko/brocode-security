namespace Brocode.Security.Core.Integrations;

public class BaseResponse
{
    public bool IsSuccess => string.IsNullOrEmpty(ErrorMessage);

    public string? ErrorMessage { get; init; }
}