using IdentityServer4.AccessTokenValidation;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using Ocelot.DependencyInjection;
using System.Net.Http.Headers;
using Microsoft.Extensions.Primitives;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

[Trait("PR", "1870")]
[Trait("Issue", "740 1580")]
public sealed class MultipleAuthSchemesFeatureTests : IdentityServerSteps
{
    private IWebHost[] _identityServers;
    private string[] _identityServerUrls;
    private BearerToken[] _tokens;

    public MultipleAuthSchemesFeatureTests() : base()
    {
        _identityServers = [];
        _identityServerUrls = [];
        _tokens = [];
    }

    public override void Dispose()
    {
        foreach (var server in _identityServers)
        {
            server.Dispose();
        }
        base.Dispose();
    }

    private MultipleAuthSchemesFeatureTests Setup(int totalSchemes)
    {
        _identityServers = new IWebHost[totalSchemes];
        _identityServerUrls = new string[totalSchemes];
        _tokens = new BearerToken[totalSchemes];
        return this;
    }

    [Theory]
    [InlineData("Test1", "Test2")] // with multiple schemes
    [InlineData(IdentityServerAuthenticationDefaults.AuthenticationScheme, "Test")] // with default scheme
    [InlineData("Test", IdentityServerAuthenticationDefaults.AuthenticationScheme)] // with default scheme
    public async Task Should_authenticate_using_identity_server_with_multiple_schemes(string scheme1, string scheme2)
    {
        var port = PortFinder.GetRandomPort();
        var route = GivenDefaultAuthRoute(port, authProviderKey: string.Empty);
        var authSchemes = new string[] { scheme1, scheme2 };
        route.AuthenticationOptions.AuthenticationProviderKeys = authSchemes;
        var configuration = GivenConfiguration(route);
        var responseBody = nameof(Should_authenticate_using_identity_server_with_multiple_schemes);

        GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK, responseBody);
        Setup(authSchemes.Length)
            .GivenIdentityServerWithScopes(0, "invalid", "unknown")
            .GivenIdentityServerWithScopes(1, "api1", "api2");
        await GivenIHaveTokenWithScope(0, "invalid"); // authentication should fail because of invalid scope
        await GivenIHaveTokenWithScope(1, "api2"); // authentication should succeed
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunningWithIdentityServerAuthSchemes("api2", authSchemes);
        GivenIHaveAddedAllAuthHeaders(authSchemes);
        await WhenIGetUrlOnTheApiGateway("/");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        ThenTheResponseBodyShouldBe(responseBody);
    }

    private MultipleAuthSchemesFeatureTests GivenIdentityServerWithScopes(int index, params string[] scopes)
    {
        var tokenType = AccessTokenType.Jwt;
        var url = _identityServerUrls[index] = DownstreamUrl(PortFinder.GetRandomPort());
        var apiScopes = scopes.Select(s => new ApiScope(s)).ToArray();
        var clients = new Client[] { DefaultClient(tokenType, apiScopes) };
        var builder = CreateIdentityServer(url, tokenType, apiScopes, clients);

        var server = _identityServers[index] = builder.Build();
        server.Start();
        VerifyIdentityServerStarted(url).Wait();
        return this;
    }

    private async Task GivenIHaveTokenWithScope(int index, string scope)
    {
        string url = _identityServerUrls[index];
        _tokens[index] = await GivenIHaveAToken(url, new ApiScope(scope));
    }

    private async Task GivenIHaveExpiredTokenWithScope(string url, string scope, int index)
    {
        _tokens[index] = await GivenAuthToken(url, scope, "expired");
    }

    private void GivenIHaveAddedAllAuthHeaders(string[] schemes)
    {
        // Assume default scheme token is attached as "Authorization" header, for example "Bearer"
        // But default authentication setup should be ignored in multiple schemes scenario
        ocelotClient.ShouldNotBeNull().DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "failed");

        for (int i = 0; i < schemes.Length && i < _tokens.Length; i++)
        {
            var token = _tokens[i];
            var header = AuthHeaderName(schemes[i]);
            var hvalue = new AuthenticationHeaderValue(token?.TokenType ?? "Bearer", token?.AccessToken);
            GivenIAddAHeader(header, hvalue.ToString());
        }
    }

    private static string AuthHeaderName(string scheme) => $"Oc-{HeaderNames.Authorization}-{scheme}";

    private void GivenOcelotIsRunningWithIdentityServerAuthSchemes(string validScope, params string[] schemes)
    {
        const string DefaultScheme = IdentityServerAuthenticationDefaults.AuthenticationScheme;
        void WithIdentityServerAuthSchemes(IServiceCollection services)
        {
            services.AddOcelot();
            var auth = services
                .AddAuthentication(options =>
                {
                    options.DefaultScheme = "MultipleSchemes";
                    options.DefaultChallengeScheme = "MultipleSchemes";
                });
            for (int i = 0; i < schemes.Length; i++)
            {
                var scheme = schemes[i];
                var identityServerUrl = _identityServerUrls[i];
                auth.AddIdentityServerAuthentication(scheme, o =>
                {
                    o.Authority = identityServerUrl;
                    o.ApiName = validScope;
                    o.ApiSecret = "secret";
                    o.RequireHttpsMetadata = false;
                    o.SupportedTokens = SupportedTokens.Both;

                    // TODO TokenRetriever ?
                    o.ForwardDefaultSelector = (context) =>
                    {
                        var headers = context.Request.Headers;
                        var name = AuthHeaderName(scheme);
                        if (headers.TryGetValue(name, out StringValues value))
                        {
                            // Redirect to default authentication handler which is (JwtAuthHandler) aka (Bearer)
                            headers[HeaderNames.Authorization] = value;
                            return scheme;
                        }

                        // Something wrong with the setup: no headers, no tokens.
                        // Redirect to default scheme to read token from default header
                        return DefaultScheme;
                    };
                });
            }
        }
        GivenOcelotIsRunning(WithIdentityServerAuthSchemes);
    }
}
