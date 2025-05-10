using IdentityServer4.AccessTokenValidation;
using IdentityServer4.Models;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Ocelot.Configuration.File;
using System.Security.Claims;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public sealed class AuthorizationTests : IdentityServerSteps
{
    public AuthorizationTests() : base()
    {
    }

    [Fact]
    public async Task Should_return_response_200_authorizing_route()
    {
        var port = PortFinder.GetRandomPort();
        var configuration = new FileConfiguration
        {
            Routes = new List<FileRoute>
            {
                new()
                {
                    DownstreamPathTemplate = "/",
                    DownstreamHostAndPorts = new List<FileHostAndPort>
                    {
                        new()
                        {
                            Host = "localhost",
                            Port = port,
                        },
                    },
                    DownstreamScheme = "http",
                    UpstreamPathTemplate = "/",
                    UpstreamHttpMethod = new List<string> { "Get" },
                    AuthenticationOptions = new FileAuthenticationOptions
                    {
                        AuthenticationProviderKeys =["Test"],
                    },
                    AddHeadersToRequest =
                    {
                        {"CustomerId", "Claims[CustomerId] > value"},
                        {"LocationId", "Claims[LocationId] > value"},
                        {"UserType", "Claims[sub] > value[0] > |"},
                        {"UserId", "Claims[sub] > value[1] > |"},
                    },
                    AddClaimsToRequest =
                    {
                        {"CustomerId", "Claims[CustomerId] > value"},
                        {"UserType", "Claims[sub] > value[0] > |"},
                        {"UserId", "Claims[sub] > value[1] > |"},
                    },
                    RouteClaimsRequirement =
                    {
                        {"UserType", "registered"},
                    },
                },
            },
        };

        await GivenThereIsAnIdentityServerRunning("api", AccessTokenType.Jwt);
        GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK, "Hello from Laura");
        await GivenIHaveAToken();
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunningWithIdentityServerAuthentication("Test");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        ThenTheResponseBodyShouldBe("Hello from Laura");
    }

    [Fact]
    public async Task Should_return_response_403_authorizing_route()
    {
        var port = PortFinder.GetRandomPort();
        var configuration = new FileConfiguration
        {
            Routes = new List<FileRoute>
            {
                new()
                {
                    DownstreamPathTemplate = "/",
                    DownstreamHostAndPorts = new List<FileHostAndPort>
                    {
                        new()
                        {
                            Host = "localhost",
                            Port = port,
                        },
                    },
                    DownstreamScheme = "http",
                    UpstreamPathTemplate = "/",
                    UpstreamHttpMethod = new List<string> { "Get" },
                    AuthenticationOptions = new FileAuthenticationOptions
                    {
                        AuthenticationProviderKeys =["Test"],
                    },
                    AddHeadersToRequest =
                    {
                        {"CustomerId", "Claims[CustomerId] > value"},
                        {"LocationId", "Claims[LocationId] > value"},
                        {"UserType", "Claims[sub] > value[0] > |"},
                        {"UserId", "Claims[sub] > value[1] > |"},
                    },
                    AddClaimsToRequest =
                    {
                        {"CustomerId", "Claims[CustomerId] > value"},
                        {"UserId", "Claims[sub] > value[1] > |"},
                    },
                    RouteClaimsRequirement =
                    {
                        {"UserType", "registered"},
                    },
                },
            },
        };

        await GivenThereIsAnIdentityServerRunning("api", AccessTokenType.Jwt);
        GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK, "Hello from Laura");
        await GivenIHaveAToken();
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunningWithIdentityServerAuthentication("Test");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/");
        ThenTheStatusCodeShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Should_return_response_200_using_identity_server_with_allowed_scope()
    {
        var port = PortFinder.GetRandomPort();
        var configuration = new FileConfiguration
        {
            Routes = new List<FileRoute>
            {
                new()
                {
                    DownstreamPathTemplate = "/",
                    DownstreamHostAndPorts = new List<FileHostAndPort>
                    {
                        new("localhost", port),
                    },
                    DownstreamScheme = "http",
                    UpstreamPathTemplate = "/",
                    UpstreamHttpMethod = new List<string> { "Get" },
                    AuthenticationOptions = new FileAuthenticationOptions
                    {
                        AuthenticationProviderKeys =["Test"],
                        AllowedScopes = new List<string>{ "api", "api.readOnly", "openid", "offline_access" },
                    },
                },
            },
        };

        await GivenThereIsAnIdentityServerRunning("api", AccessTokenType.Jwt);
        GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK, "Hello from Laura");
        await GivenIHaveAToken(new ApiScope("api.readOnly"));
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunningWithIdentityServerAuthentication("Test");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Should_return_response_403_using_identity_server_with_scope_not_allowed()
    {
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
                        AllowedScopes = ["api", "openid", "offline_access"],
                    },
                },
            ],
        };

        await GivenThereIsAnIdentityServerRunning("api", AccessTokenType.Jwt);
        GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK, "Hello from Laura");
        await GivenIHaveAToken(new ApiScope("api.readOnly"));
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunningWithIdentityServerAuthentication("Test");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/");
        ThenTheStatusCodeShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    [Trait("OcBug", "https://github.com/ThreeMammals/Ocelot/issues/240")]
    public async Task Should_fix_issue_240()
    {
        var port = PortFinder.GetRandomPort();
        var configuration = new FileConfiguration
        {
            Routes = [
                new()
                {
                    DownstreamPathTemplate = "/",
                    DownstreamHostAndPorts = [ Localhost(port) ],
                    DownstreamScheme = Uri.UriSchemeHttp,
                    UpstreamPathTemplate = "/",
                    UpstreamHttpMethod = [ HttpMethods.Get ],
                    AuthenticationOptions = new()
                    {
                        AuthenticationProviderKeys = ["Test"],
                    },
                    RouteClaimsRequirement =
                    {
                        {"Role", "User"},
                    },
                },
            ],
        };
        var users = new List<TestUser>
        {
            new()
            {
                Username = "test",
                Password = "test",
                SubjectId = "registered|1231231",
                Claims = [
                    new("Role", "AdminUser"),
                    new("Role", "User"),
                ],
            },
        };
        await GivenThereIsAnIdentityServerRunning("api", AccessTokenType.Jwt, users);
        GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK, "Hello from Laura");
        await GivenIHaveAToken();
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunningWithIdentityServerAuthentication("Test");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        ThenTheResponseBodyShouldBe("Hello from Laura");
    }

    private Task GivenThereIsAnIdentityServerRunning(string apiName, AccessTokenType tokenType)
    {
        void WithServices(IServiceCollection services)
        {
            services.AddLogging();
            services.AddIdentityServer()
                .AddDeveloperSigningCredential()
                .AddInMemoryApiScopes([
                    new(apiName, "test"),
                    new("openid", "test"),
                    new("offline_access", "test"),
                    new("api.readOnly", "test"),
                ])
                .AddInMemoryApiResources([
                    new()
                    {
                        Name = apiName,
                        Description = "My API",
                        Enabled = true,
                        DisplayName = "test",
                        Scopes = ["api", "api.readOnly", "openid", "offline_access"],
                        ApiSecrets = [
                            new() { Value = "secret".Sha256() },
                        ],
                        UserClaims = ["CustomerId", "LocationId", "UserType", "UserId"],
                    },
                ])
                .AddInMemoryClients([
                    new()
                    {
                        ClientId = "client",
                        AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
                        ClientSecrets = [ new("secret".Sha256()) ],
                        AllowedScopes = [apiName, "api.readOnly", "openid", "offline_access"],
                        AccessTokenType = tokenType,
                        Enabled = true,
                        RequireClientSecret = false,
                    },
                ])
                .AddTestUsers([
                    new()
                    {
                        Username = "test",
                        Password = "test",
                        SubjectId = "registered|1231231",
                        Claims = [
                            new("CustomerId", "123"),
                            new("LocationId", "321"),
                        ],
                    },
                ]);
        }
        return GivenThereIsAnIdentityServerRunning(WithServices);
    }

    private Task GivenThereIsAnIdentityServerRunning(string apiName, AccessTokenType tokenType, List<TestUser> users)
    {
        void WithServices(IServiceCollection services)
        {
            services.AddLogging();
            services.AddIdentityServer()
                .AddDeveloperSigningCredential()
                .AddInMemoryApiScopes([
                    new(apiName, "test"),
                ])
                .AddInMemoryApiResources([
                    new()
                    {
                        Name = apiName,
                        Description = "My API",
                        Enabled = true,
                        DisplayName = "test",
                        Scopes = ["api", "api.readOnly", "openid", "offline_access"],
                        ApiSecrets = [
                            new() { Value = "secret".Sha256() }
                        ],
                        UserClaims = ["CustomerId", "LocationId", "UserType", "UserId", "Role"],
                    },
                ])
                .AddInMemoryClients([
                    new()
                    {
                        ClientId = "client",
                        AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
                        ClientSecrets = [ new("secret".Sha256()) ],
                        AllowedScopes = [apiName, "api.readOnly", "openid", "offline_access"],
                        AccessTokenType = tokenType,
                        Enabled = true,
                        RequireClientSecret = false,
                    },
                ])
                .AddTestUsers(users);
        }
        return GivenThereIsAnIdentityServerRunning(WithServices);
    }
}
