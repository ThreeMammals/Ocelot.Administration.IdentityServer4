using IdentityServer4.AccessTokenValidation;
using IdentityServer4.Models;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Ocelot.Configuration.File;
using System.IO;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public sealed class ClaimsToDownstreamPathTests : IdentityServerSteps
{
    private string? _downstreamFinalPath;

    public ClaimsToDownstreamPathTests() : base()
    {
    }

    [Fact]
    public async Task Should_return_200_and_change_downstream_path()
    {
        var user = new TestUser
        {
            Username = "test",
            Password = "test",
            SubjectId = "registered|1231231",
        };
        var port = PortFinder.GetRandomPort();
        var configuration = new FileConfiguration
        {
            Routes = new()
            {
                new()
                {
                    DownstreamPathTemplate = "/users/{userId}",
                    DownstreamHostAndPorts = [ Localhost(port) ],
                    DownstreamScheme = "http",
                    UpstreamPathTemplate = "/users/{userId}",
                    UpstreamHttpMethod = [HttpMethods.Get],
                    AuthenticationOptions = new()
                    {
                        AuthenticationProviderKey = "Test",
                        AllowedScopes = ["openid", "offline_access", "api"],
                    },
                    ChangeDownstreamPathTemplate =
                    {
                        {"userId", "Claims[sub] > value[1] > |"},
                    },
                },
            },
        };
        await GivenThereIsAnIdentityServer("api", AccessTokenType.Jwt, [user]);
        GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK);
        await GivenIHaveAToken();
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunningWithIdentityServerAuthentication("Test");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/users");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        ThenTheResponseBodyShouldBe("UserId: 1231231");
        _downstreamFinalPath.ShouldBe("/users/1231231");
    }

    private void GivenThereIsAServiceRunningOn(int port, HttpStatusCode statusCode)
    {
        string url = DownstreamUrl(port);
        handler.GivenThereIsAServiceRunningOn(url, async context =>
        {
            _downstreamFinalPath = context.Request.Path.Value ?? string.Empty;
            var userId = _downstreamFinalPath.Replace("/users/", string.Empty);
            var responseBody = $"UserId: {userId}";
            context.Response.StatusCode = (int)statusCode;
            await context.Response.WriteAsync(responseBody);
        });
    }

    /*
    private async Task GivenThereIsAnIdentityServerOn(string url, string apiName, AccessTokenType tokenType, TestUser user)
    {
        _identityServerBuilder = TestHostBuilder.Create()
            .UseUrls(url)
            .UseKestrel()
            .UseContentRoot(Directory.GetCurrentDirectory())
            .UseIISIntegration()
            .UseUrls(url)
            .ConfigureServices(services =>
            {
                services.AddLogging();
                services.AddIdentityServer()
                    .AddDeveloperSigningCredential()
                    .AddInMemoryApiScopes(new List<ApiScope>
                    {
                        new(apiName, "test"),
                        new("openid", "test"),
                        new("offline_access", "test"),
                        new("api.readOnly", "test"),
                    })
                    .AddInMemoryApiResources(new List<ApiResource>
                    {
                        new()
                        {
                            Name = apiName,
                            Description = "My API",
                            Enabled = true,
                            DisplayName = "test",
                            Scopes = new List<string>
                            {
                                "api",
                                "openid",
                                "offline_access",
                            },
                            ApiSecrets = new List<Secret>
                            {
                                new()
                                {
                                    Value = "secret".Sha256(),
                                },
                            },
                            UserClaims = new List<string>
                            {
                                "CustomerId", "LocationId", "UserType", "UserId",
                            },
                        },
                    })
                    .AddInMemoryClients(new List<Client>
                    {
                        new()
                        {
                            ClientId = "client",
                            AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
                            ClientSecrets = new List<Secret> {new("secret".Sha256())},
                            AllowedScopes = new List<string> { apiName, "openid", "offline_access" },
                            AccessTokenType = tokenType,
                            Enabled = true,
                            RequireClientSecret = false,
                        },
                    })
                    .AddTestUsers(new List<TestUser>
                    {
                        user,
                    });
            })
            .Configure(app =>
            {
                app.UseIdentityServer();
            })
            .Build();

        await _identityServerBuilder.StartAsync();
        await VerifyIdentityServerStarted(url);
    }*/
}
