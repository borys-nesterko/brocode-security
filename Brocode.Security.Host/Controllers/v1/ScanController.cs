using Microsoft.AspNetCore.Mvc;
using Brocode.Security.Host.Models;
using Brocode.Security.Core.Abstractions;
using Brocode.Security.Application.Models;
using System.Buffers.Text;
using Brocode.Security.Core.Models;

namespace Brocode.Security.Host.Controllers.v1;

[ApiVersion("1.0")]
[Route("api/v{v:apiVersion}/scan")]
public class ScanController(
    IGetVulnerabilitiesQueryHandler queryHandler) : ControllerBase
{
    /// <summary>
    /// Scans the provided package file content for known vulnerabilities.
    /// </summary>
    /// <param name="request"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    [HttpPost]
    [ProducesResponseType(typeof(ScanPackagesResult), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Scan(
        [FromBody] ScanRequest request,
        CancellationToken cancellationToken = default)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        if (!Base64.IsValid(request.FileContent))
        {
            return BadRequest($"The {nameof(ScanRequest.FileContent)} field must be a valid Base64-encoded string.");
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