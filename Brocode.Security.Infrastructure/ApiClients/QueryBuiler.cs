using System.Text.Json;

namespace Brocode.Security.Infrastructure.ApiClients;

public class QueryBuilder
{
    private string _ecosystem;
    private string _packageName;

    public QueryBuilder WithEcosystem(string ecosystem)
    {
        ArgumentException.ThrowIfNullOrEmpty(ecosystem);
        _ecosystem = ecosystem;
        return this;
    }

    public QueryBuilder WithPackageName(string packageName)
    {
        ArgumentException.ThrowIfNullOrEmpty(packageName);
        _packageName = packageName;
        return this;
    }


    public string Build() => JsonSerializer.Serialize(new
    {
        query = $@"{{
            securityVulnerabilities(ecosystem: {_ecosystem.ToUpper()}, first: 100, package: ""{_packageName}"") {{
                nodes {{
                    severity
                    advisory {{
                        summary
                    }}
                    package {{
                        name
                        ecosystem
                    }}
                    vulnerableVersionRange
                    firstPatchedVersion {{
                        identifier
                    }}
                }}
            }}
        }}"
    });
}