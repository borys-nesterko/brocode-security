namespace Brocode.Security.Core.Integrations.GitHub;

public sealed class GitHubResponse : BaseResponse
{
    public DataResponse? Data { get; set; }
}

public class DataResponse
{
    public SecurityVulnerabilities? SecurityVulnerabilities { get; set; }
}

public class SecurityVulnerabilities
{
    public SecurityVulnerability[]? Nodes { get; set; }
}

public class SecurityVulnerability
{
    public string? Severity { get; set; }
    public Advisory? Advisory { get; set; }
    public Package? Package { get; set; }
    public string? VulnerableVersionRange { get; set; }
    public FirstPatchedVersion? FirstPatchedVersion { get; set; }
}

public class FirstPatchedVersion
{
    public string? Identifier { get; set; }
}

public class Package
{
    public string? Name { get; set; }
    public string? Ecosystem { get; set; }
}

public class Advisory
{
    public string? Summary { get; set; }
}

