using IdentityServer4.AccessTokenValidation;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Http;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public sealed class AuthenticationTests : IdentityServerSteps
{
    public AuthenticationTests() : base()
    {
    }

    [Fact]
    public async Task Should_return_401_using_identity_server_access_token()
    {
        var port = PortFinder.GetRandomPort();
        var route = GivenDefaultAuthRoute(port, HttpMethods.Post);
        var configuration = GivenConfiguration(route);
        await GivenThereIsAnIdentityServer(AccessTokenType.Jwt);
        GivenThereIsAServiceRunningOn(port, HttpStatusCode.Created, string.Empty);
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunningWithIdentityServerAuthentication("Test");
        await WhenIPostUrlOnTheApiGateway("/", content: nameof(Should_return_401_using_identity_server_access_token));
        ThenTheStatusCodeShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Should_return_response_200_using_identity_server()
    {
        var port = PortFinder.GetRandomPort();
        var route = GivenDefaultAuthRoute(port);
        var configuration = GivenConfiguration(route);
        await GivenThereIsAnIdentityServer(AccessTokenType.Jwt);
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
    public async Task Should_return_response_401_using_identity_server_with_token_requested_for_other_api()
    {
        var port = PortFinder.GetRandomPort();
        var route = GivenDefaultAuthRoute(port);
        var configuration = GivenConfiguration(route);
        await GivenThereIsAnIdentityServer(AccessTokenType.Jwt);
        GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK, "Hello from Laura");
        await GivenIHaveAToken(new ApiScope("api2"));
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunningWithIdentityServerAuthentication("Test");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/");
        ThenTheStatusCodeShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Should_return_201_using_identity_server_access_token()
    {
        var port = PortFinder.GetRandomPort();
        var route = GivenDefaultAuthRoute(port, HttpMethods.Post);
        var configuration = GivenConfiguration(route);
        await GivenThereIsAnIdentityServer(AccessTokenType.Jwt);
        GivenThereIsAServiceRunningOn(port, HttpStatusCode.Created, string.Empty);
        await GivenIHaveAToken();
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunningWithIdentityServerAuthentication("Test");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIPostUrlOnTheApiGateway("/", content: nameof(Should_return_201_using_identity_server_access_token));
        ThenTheStatusCodeShouldBe(HttpStatusCode.Created);
    }

    [Fact]
    public async Task Should_return_201_using_identity_server_reference_token()
    {
        var port = PortFinder.GetRandomPort();
        var route = GivenDefaultAuthRoute(port, HttpMethods.Post);
        var configuration = GivenConfiguration(route);
        await GivenThereIsAnIdentityServer(AccessTokenType.Reference);
        GivenThereIsAServiceRunningOn(port, HttpStatusCode.Created, string.Empty);
        await GivenIHaveAToken();
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunningWithIdentityServerAuthentication("Test");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIPostUrlOnTheApiGateway("/", content: nameof(Should_return_201_using_identity_server_reference_token));
        ThenTheStatusCodeShouldBe(HttpStatusCode.Created);
    }
}
