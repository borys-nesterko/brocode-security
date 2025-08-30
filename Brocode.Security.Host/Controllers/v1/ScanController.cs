using Microsoft.AspNetCore.Mvc;
using Brocode.Security.Host.Models;
using Brocode.Security.Core.Abstractions;
using Brocode.Security.Application.Models;

namespace Brocode.Security.Host.Controllers.v1;

[ApiVersion("1.0")]
[Route("api/v{v:apiVersion}/scan")]
public class ScanController(
    IGetVulnerabilitiesQueryHandler queryHandler) : ControllerBase
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

        var scanQuery = new GetVulnerabilitiesQuery
        {
            Id = Guid.NewGuid(),
            Ecosystem = request.Ecosystem,
            FileContent = request.FileContent
        };

        var scanResult = await queryHandler.ProcessQueryAsync(scanQuery, cancellationToken);

        if (!scanResult.IsSuccess)
        {
            return StatusCode(400, scanResult.ErrorMessage);
        }

        return Ok(scanResult);
    }
}