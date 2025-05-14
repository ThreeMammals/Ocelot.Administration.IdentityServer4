using IdentityServer4.Models;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Http;

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
        var port = PortFinder.GetRandomPort();
        var route = GivenRoute(port, "/users/{userId}", "/users/{userId}");
        route.AuthenticationOptions = new()
        {
            AuthenticationProviderKeys = ["Test"],
            AllowedScopes = ["openid", "offline_access", "api"],
        };
        route.ChangeDownstreamPathTemplate.Add("userId", "Claims[sub] > value[1] > |");
        var configuration = GivenConfiguration(route);
        var user = new TestUser
        {
            Username = "test",
            Password = "test",
            SubjectId = "registered|1231231",
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

    private void GivenThereIsAServiceRunningOn(int port, HttpStatusCode statusCode) =>
        handler.GivenThereIsAServiceRunningOn(port, context =>
        {
            _downstreamFinalPath = context.Request.Path.Value ?? string.Empty;
            var userId = _downstreamFinalPath.Replace("/users/", string.Empty);
            var responseBody = $"UserId: {userId}";
            context.Response.StatusCode = (int)statusCode;
            return context.Response.WriteAsync(responseBody);
        });
}
