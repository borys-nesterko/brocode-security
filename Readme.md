Brocode.Security serves as a single platform for validating CI/CD vulnerabilities. That is achieved by integrating with third-party vendors.

To run application place your GITHUB TOKEN into appsettings.json and execute 'dotnet run --project .\Brocode.Security.Host\'

With adding of new responsibilities to scanning job I would suggest rewritting it to pipeline with several stages. In such a way all concerns will be isolated and replacable. 

Unit tests cover 2 basic scenrious, but for real life application I would cover all possible edge cases.