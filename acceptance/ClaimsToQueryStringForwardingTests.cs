using IdentityServer4.AccessTokenValidation;
using IdentityServer4.Configuration;
using IdentityServer4.Models;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Ocelot.Configuration.File;
using System.Reflection.Metadata;
using System.Security.Claims;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public sealed class ClaimsToQueryStringForwardingTests : IdentityServerSteps
{
    private string? _downstreamQueryString;

    public ClaimsToQueryStringForwardingTests() : base()
    {
    }

    [Fact]
    public async Task Should_return_response_200_and_foward_claim_as_query_string()
    {
        var user = new TestUser
        {
            Username = "test",
            Password = "test",
            SubjectId = "registered|1231231",
            Claims = [
                new("CustomerId", "123"),
                new("LocationId", "1"),
            ],
        };
        var port = PortFinder.GetRandomPort();
        var configuration = new FileConfiguration
        {
            Routes =
            [
                new()
                {
                    DownstreamPathTemplate = "/",
                    DownstreamHostAndPorts = [ Localhost(port) ],
                    DownstreamScheme = "http",
                    UpstreamPathTemplate = "/",
                    UpstreamHttpMethod = ["Get"],
                    AuthenticationOptions = new()
                    {
                        AuthenticationProviderKeys = ["Test"],
                        AllowedScopes = ["openid", "offline_access", "api"],
                    },
                    AddQueriesToRequest =
                    {
                        {"CustomerId", "Claims[CustomerId] > value"},
                        {"LocationId", "Claims[LocationId] > value"},
                        {"UserType", "Claims[sub] > value[0] > |"},
                        {"UserId", "Claims[sub] > value[1] > |"},
                    },
                },
            ],
        };

        await GivenThereIsAnIdentityServer("api", AccessTokenType.Jwt, [user]);
        GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK);
        await GivenIHaveAToken();
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunningWithIdentityServerAuthentication("Test");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        ThenTheResponseBodyShouldBe("CustomerId: 123 LocationId: 1 UserType: registered UserId: 1231231");
    }

    [Fact]
    public async Task Should_return_response_200_and_foward_claim_as_query_string_and_preserve_original_string()
    {
        var user = new TestUser
        {
            Username = "test",
            Password = "test",
            SubjectId = "registered|1231231",
            Claims =
            [
                new("CustomerId", "123"),
                new("LocationId", "1"),
            ],
        };
        var port = PortFinder.GetRandomPort();
        var configuration = new FileConfiguration
        {
            Routes =
            [
                new()
                {
                    DownstreamPathTemplate = "/",
                    DownstreamHostAndPorts = [ Localhost(port) ],
                    DownstreamScheme = "http",
                    UpstreamPathTemplate = "/",
                    UpstreamHttpMethod = ["Get"],
                    AuthenticationOptions = new()
                    {
                        AuthenticationProviderKeys = ["Test"],
                        AllowedScopes = ["openid", "offline_access", "api"],
                    },
                    AddQueriesToRequest =
                    {
                        {"CustomerId", "Claims[CustomerId] > value"},
                        {"LocationId", "Claims[LocationId] > value"},
                        {"UserType", "Claims[sub] > value[0] > |"},
                        {"UserId", "Claims[sub] > value[1] > |"},
                    },
                },
            ],
        };

        await GivenThereIsAnIdentityServer("api", AccessTokenType.Jwt, [user]);
        GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK);
        await GivenIHaveAToken();
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunningWithIdentityServerAuthentication("Test");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/?test=1&test=2");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        ThenTheResponseBodyShouldBe("CustomerId: 123 LocationId: 1 UserType: registered UserId: 1231231");
        _downstreamQueryString.ShouldBe("?test=1&test=2&CustomerId=123&LocationId=1&UserId=1231231&UserType=registered");
    }

    private void GivenThereIsAServiceRunningOn(int port, HttpStatusCode statusCode)
    {
        string url = DownstreamUrl(port);
        handler.GivenThereIsAServiceRunningOn(url, async context =>
        {
            _downstreamQueryString = context.Request.QueryString.Value;
            context.Request.Query.TryGetValue("CustomerId", out var customerId);
            context.Request.Query.TryGetValue("LocationId", out var locationId);
            context.Request.Query.TryGetValue("UserType", out var userType);
            context.Request.Query.TryGetValue("UserId", out var userId);
            var responseBody = $"CustomerId: {customerId} LocationId: {locationId} UserType: {userType} UserId: {userId}";
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
        await Steps.VerifyIdentityServerStarted(url);
    }*/
}
