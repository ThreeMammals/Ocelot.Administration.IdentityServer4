using IdentityServer4.Models;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Http;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public sealed class ClaimsToHeadersForwardingTests : IdentityServerSteps
{
    public ClaimsToHeadersForwardingTests()
    { }

    [Fact]
    public async Task Should_return_response_200_and_foward_claim_as_header()
    {
        var port = PortFinder.GetRandomPort();
        var route = GivenDefaultRoute(port);
        route.AuthenticationOptions = new()
        {
            AuthenticationProviderKeys = ["Test"],
            AllowedScopes = ["openid", "offline_access", "api"],
        };
        route.AddHeadersToRequest = new()
        {
            {"CustomerId", "Claims[CustomerId] > value"},
            {"LocationId", "Claims[LocationId] > value"},
            {"UserType", "Claims[sub] > value[0] > |"},
            {"UserId", "Claims[sub] > value[1] > |"},
        };
        var configuration = GivenConfiguration(route);
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

    private void GivenThereIsAServiceRunningOn(int port, HttpStatusCode statusCode) =>
        handler.GivenThereIsAServiceRunningOn(port, context =>
        {
            var customerId = context.Request.Headers.First(x => x.Key == "CustomerId").Value.First();
            var locationId = context.Request.Headers.First(x => x.Key == "LocationId").Value.First();
            var userType = context.Request.Headers.First(x => x.Key == "UserType").Value.First();
            var userId = context.Request.Headers.First(x => x.Key == "UserId").Value.First();
            var responseBody = $"CustomerId: {customerId} LocationId: {locationId} UserType: {userType} UserId: {userId}";
            context.Response.StatusCode = (int)statusCode;
            return context.Response.WriteAsync(responseBody);
        });
}
