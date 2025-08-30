using Brocode.Security.Core.Models;

namespace Brocode.Security.Core.Abstractions;

public interface IScanPipeline                                                                                        
{
    Task<ScanPackagesResult> ScanPacakagesAsync(ScanPackagesQuery query);                                                                                                                                                       
}