using Microsoft.AspNetCore.Mvc;
using Brocode.Security.Host.Models;
using Brocode.Security.Core.Abstractions;
using Brocode.Security.Core.Models;

namespace Brocode.Security.Host.Controllers.v1;

[ApiVersion("1.0")]
[Route("api/v{v:apiVersion}/scan")]
public class ScanController(
    IVulnerabilitiesScanner vulnerabilitiesScanner) : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> Scan(
        [FromBody] ScanRequest request,
        CancellationToken cancellationToken = default)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var scanQuery = new ScanPackagesQuery
        {
            Id = Guid.NewGuid(),
            Ecosystem = request.Ecosystem,
            Content = request.FileContent
        };

        var scanResult = await vulnerabilitiesScanner.ScanAsync(scanQuery, cancellationToken);

        return Ok(scanResult);
    }
}