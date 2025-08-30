using Brocode.Security.Core.Enums;

namespace Brocode.Security.Host.Models;

public class ScanRequest
{
    public Ecosystem Ecosystem { get; set; }

    public required string FileContent { get; set; }
}   