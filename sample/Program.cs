using Ocelot.Administration.IdentityServer4;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
//using Ocelot.Samples.Web;

// var host = OcelotHostBuilder.Create(args);
var builder = WebApplication.CreateBuilder(args);

builder.Configuration
    .SetBasePath(builder.Environment.ContentRootPath)
    //.AddOcelot() not available in v23.4, but it will be in v24.0 // single ocelot.json file in read-only mode
    .AddOcelot(builder.Environment); // single ocelot.json file with merging

builder.Services
    .AddOcelot(builder.Configuration)
    .AddAdministration("/administration", "secret");

if (builder.Environment.IsDevelopment())
{
    builder.Logging.AddConsole();
}

var app = builder.Build();
await app.UseOcelot();
await app.RunAsync();
