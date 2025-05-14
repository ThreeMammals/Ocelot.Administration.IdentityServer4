using IdentityServer4.Models;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Http;
using Ocelot.Configuration.File;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public sealed class ClaimsToQueryStringForwardingTests : IdentityServerSteps
{
    private string? _downstreamQueryString;

    public ClaimsToQueryStringForwardingTests() : base()
    { }

    [Fact]
    public async Task Should_return_response_200_and_foward_claim_as_query_string()
    {
        var port = PortFinder.GetRandomPort();
        var route = GivenRoute(port);
        var configuration = GivenConfiguration(route);
        await GivenThereIsAnIdentityServer("api", AccessTokenType.Jwt, [GivenUser()]);
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
        var port = PortFinder.GetRandomPort();
        var route = GivenRoute(port);
        var configuration = GivenConfiguration(route);
        await GivenThereIsAnIdentityServer("api", AccessTokenType.Jwt, [GivenUser()]);
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

    private static TestUser GivenUser() => new()
    {
        Username = "test",
        Password = "test",
        SubjectId = "registered|1231231",
        Claims = [
            new ("CustomerId", "123"),
            new ("LocationId", "1"),
        ],
    };

    private static FileRoute GivenRoute(int port)
    {
        var route = GivenDefaultRoute(port);
        route.AuthenticationOptions = new()
        {
            AuthenticationProviderKeys = ["Test"],
            AllowedScopes = ["openid", "offline_access", "api"],
        };
        route.AddQueriesToRequest = new()
        {
            { "CustomerId", "Claims[CustomerId] > value" },
            { "LocationId", "Claims[LocationId] > value" },
            { "UserType", "Claims[sub] > value[0] > |" },
            { "UserId", "Claims[sub] > value[1] > |" },
        };
        return route;
    }

    private void GivenThereIsAServiceRunningOn(int port, HttpStatusCode statusCode) =>
        handler.GivenThereIsAServiceRunningOn(port, context =>
        {
            _downstreamQueryString = context.Request.QueryString.Value;
            context.Request.Query.TryGetValue("CustomerId", out var customerId);
            context.Request.Query.TryGetValue("LocationId", out var locationId);
            context.Request.Query.TryGetValue("UserType", out var userType);
            context.Request.Query.TryGetValue("UserId", out var userId);
            var responseBody = $"CustomerId: {customerId} LocationId: {locationId} UserType: {userType} UserId: {userId}";
            context.Response.StatusCode = (int)statusCode;
            return context.Response.WriteAsync(responseBody);
        });
}
