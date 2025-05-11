using IdentityServer4.AccessTokenValidation;
using IdentityServer4.Models;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using Ocelot.Configuration.File;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using System;
using System.Security.Policy;
using System.Text.Json;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public class IdentityServerSteps : AcceptanceSteps
{
    protected BearerToken? token;
    protected readonly ServiceHandler handler;
    private readonly int _identityServerPort;
    private readonly string _identityServerUrl;
    private IWebHost? _identityServer;

    public IdentityServerSteps() : base()
    {
        handler = new ServiceHandler();
        _identityServerPort = PortFinder.GetRandomPort();
        _identityServerUrl = DownstreamUrl(_identityServerPort);
    }

    public override void Dispose()
    {
        handler.Dispose();
        _identityServer?.Dispose();
        base.Dispose();
        GC.SuppressFinalize(this);
    }

    public static ApiResource CreateApiResource(string apiName, IEnumerable<string>? extraScopes = null)
        => new()
        {
            Name = apiName,
            Description = $"My {apiName} API",
            Enabled = true,
            DisplayName = "test",
            Scopes =
            [
                .. extraScopes ?? [],
                apiName,
                $"{apiName}.readOnly",
            ],
            ApiSecrets =
            [
                new ("secret".Sha256()),
            ],
            UserClaims =
            [
                "CustomerId",
                "LocationId",
            ],
        };

    protected static Client CreateClientWithSecret(string clientId, Secret secret, AccessTokenType tokenType = AccessTokenType.Jwt, ApiScope[]? scopes = null)
    {
        var client = DefaultClient(tokenType, scopes);
        client.ClientId = clientId ?? "client";
        client.ClientSecrets = [secret];
        return client;
    }

    protected static Client DefaultClient(AccessTokenType tokenType = AccessTokenType.Jwt, ApiScope[]? apiScopes = null)
    {
        apiScopes ??= [ new("api") ];
        return new()
        {
            ClientId = "client",
            AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
            ClientSecrets = [ new("secret".Sha256()) ],
            AllowedScopes = [.. apiScopes
                .Select(s => s.Name)
                .Union(apiScopes.Select(x => $"{x.Name}.readOnly"))
                .Union(["openid", "offline_access"])
            ],
            AccessTokenType = tokenType,
            Enabled = true,
            RequireClientSecret = false,
            RefreshTokenExpiration = TokenExpiration.Absolute,
        };
    }

    public static IWebHostBuilder CreateIdentityServer(string url, AccessTokenType tokenType, ApiScope[] apiScopes, Client[]? clients = null, TestUser[]? users = null)
    {
        apiScopes ??= [ new("api") ];
        clients ??= [ DefaultClient(tokenType, apiScopes) ];
        users ??= [new()
        {
            Username = "test",
            Password = "test",
            SubjectId = "registered|1231231",
            Claims = [
                new("CustomerId", "123"),
                new("LocationId", "321"),
            ],
        }];
        var builder = TestHostBuilder.Create()
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
                    .AddInMemoryApiScopes(apiScopes)
                    .AddInMemoryApiResources(apiScopes
                        .Select(x => new { i = Array.IndexOf(apiScopes, x), scope = x })
                        .Select(x => CreateApiResource(x.scope.Name, ["openid", "offline_access"])))
                    .AddInMemoryClients(clients)
                    .AddTestUsers([.. users]);
            })
            .Configure(app =>
            {
                app.UseIdentityServer();
            });
        return builder;
    }

    protected Task GivenThereIsAnIdentityServerRunning(Action<IServiceCollection> configureServices)
    {
        var builder = TestHostBuilder.Create()
            .UseUrls(_identityServerUrl)
            .UseKestrel()
            .UseContentRoot(Directory.GetCurrentDirectory())
            .UseIISIntegration()
            .UseUrls(_identityServerUrl)
            .ConfigureServices(configureServices)
            .Configure(app => app.UseIdentityServer());
        _identityServer = builder.Build();
        return _identityServer.StartAsync()
            .ContinueWith(t => VerifyIdentityServerStarted(_identityServerUrl));
    }

    protected async Task GivenThereIsAnIdentityServerOn(string url, string apiName)
    {
        var tokenType = AccessTokenType.Jwt;
        ApiScope[] scopes = [ new(apiName) ];
        var clients = new Client[] { DefaultClient(tokenType, scopes) };
        var builder = CreateIdentityServer(url, tokenType, scopes, clients);
        _identityServer = builder.Build();
        await _identityServer.StartAsync();
        await VerifyIdentityServerStarted(url);
    }

    protected async Task GivenThereIsAnIdentityServer(AccessTokenType tokenType)
    {
        var scopes = new ApiScope[] { new("api"), new("api2") };
        _identityServer = CreateIdentityServer(_identityServerUrl, tokenType, scopes)
            .Build();
        await _identityServer.StartAsync();
        await VerifyIdentityServerStarted(_identityServerUrl);
    }

    protected async Task GivenThereIsAnIdentityServer(string apiName, AccessTokenType tokenType)
    {
        var scopes = new ApiScope[] { new(apiName) };
        _identityServer = CreateIdentityServer(_identityServerUrl, tokenType, scopes)
            .Build();
        await _identityServer.StartAsync();
        await VerifyIdentityServerStarted(_identityServerUrl);
    }

    protected async Task GivenThereIsAnIdentityServer(string apiName, AccessTokenType tokenType, IEnumerable<TestUser> users)
    {
        var scopes = new ApiScope[] { new(apiName) };
        _identityServer = CreateIdentityServer(_identityServerUrl, tokenType, scopes, users: [.. users])
            .Build();
        await _identityServer.StartAsync();
        await VerifyIdentityServerStarted(_identityServerUrl);
    }

    protected void GivenIHaveAddedATokenToMyRequest() => GivenIHaveAddedATokenToMyRequest(token);
    public void GivenIHaveAddedATokenToMyRequest(BearerToken? token) => GivenIHaveAddedATokenToMyRequest(token?.AccessToken ?? string.Empty, "Bearer");

    internal Task<BearerToken> GivenIHaveAToken(ApiScope scope)
        => GivenIHaveAToken(_identityServerUrl, scope);
    internal Task<BearerToken> GivenIHaveAToken(string url, ApiScope apiScope)
    {
        var form = GivenDefaultAuthTokenForm();
        form.RemoveAll(x => x.Key == "scope");
        form.Add(new("scope", apiScope.Name));
        return GivenIHaveATokenWithForm(url, form);
    }

    internal Task<BearerToken> GivenAuthToken(string url, string apiScope, string client)
    {
        var form = GivenDefaultAuthTokenForm();

        form.RemoveAll(x => x.Key == "scope");
        form.Add(new("scope", apiScope));

        form.RemoveAll(x => x.Key == "client_id");
        form.Add(new("client_id", client));

        return GivenIHaveATokenWithForm(url, form);
    }

    public static List<KeyValuePair<string, string>> GivenDefaultAuthTokenForm() =>
    [
        new ("client_id", "client"),
        new ("client_secret", "secret"),
        new ("scope", "api"),
        new ("username", "test"),
        new ("password", "test"),
        new ("grant_type", "password"),
    ];

    protected Task<BearerToken> GivenIHaveAToken() => GivenIHaveAToken(_identityServerUrl);
    internal Task<BearerToken> GivenIHaveAToken(string url)
    {
        var form = GivenDefaultAuthTokenForm();
        return GivenIHaveATokenWithForm(url, form);
    }

    internal async Task<BearerToken> GivenIHaveATokenWithForm(string url, IEnumerable<KeyValuePair<string, string>> form, HttpClient? client = null)
    {
        var tokenUrl = $"{url}/connect/token";
        var formData = form ?? [];
        var content = new FormUrlEncodedContent(formData);
        client ??= new HttpClient();
        var response = await client.PostAsync(tokenUrl, content);

        var responseContent = await response.Content.ReadAsStringAsync();
        response.EnsureSuccessStatusCode();
        return token = JsonConvert.DeserializeObject<BearerToken>(responseContent) ?? new();
    }

    public async Task VerifyIdentityServerStarted(string url, HttpClient? client = null)
    {
        client ??= new HttpClient();
        var response = await client.GetAsync($"{url}/.well-known/openid-configuration");
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync();
        json.ShouldNotBeNullOrEmpty();
        var jEl = System.Text.Json.JsonSerializer.Deserialize<JsonElement>(json);
        var issuer = jEl.GetProperty("issuer").GetString().ShouldNotBeNull();
        bool issuedBy = issuer.Contains("Ocelot")
            || issuer.Contains(_identityServerUrl)
            || (client.BaseAddress == null && issuer.Contains(url));
        issuedBy.ShouldBeTrue();
    }

    protected Task GivenIHaveAdministrationToken(string adminPath)
    {
        var formData = new List<KeyValuePair<string, string>>
        {
            new("client_id", "admin"),
            new("client_secret", "secret"),
            new("scope", "admin"),
            new("grant_type", "client_credentials"),
        };
        return GivenIHaveATokenWithForm(adminPath, formData, ocelotClient)
            .ContinueWith(t => VerifyIdentityServerStarted(adminPath, ocelotClient));
    }

    public static FileRoute GivenDefaultAuthRoute(int port, string? upstreamHttpMethod = null, string? authProviderKey = null) => new()
    {
        DownstreamPathTemplate = "/",
        DownstreamHostAndPorts = [ Localhost(port) ],
        DownstreamScheme = Uri.UriSchemeHttp,
        UpstreamPathTemplate = "/",
        UpstreamHttpMethod = [upstreamHttpMethod ?? HttpMethods.Get],
        AuthenticationOptions = new()
        {
            AuthenticationProviderKeys = [authProviderKey ?? "Test"],
        },
    };

    protected void GivenThereIsAServiceRunningOn(int port, HttpStatusCode statusCode, string responseBody) =>
        handler.GivenThereIsAServiceRunningOn(port, async context =>
        {
            context.Response.StatusCode = (int)statusCode;
            await context.Response.WriteAsync(responseBody);
        });

    private void WithOptions(IdentityServerAuthenticationOptions o)
    {
        o.Authority = _identityServerUrl;
        o.ApiName = "api";
        o.RequireHttpsMetadata = false;
        o.SupportedTokens = SupportedTokens.Both;
        o.ApiSecret = "secret";
    }

    public void GivenOcelotIsRunningWithIdentityServerAuthentication(string authenticationProviderKey)
    {
        void WithIdentityServerAuthentication(IServiceCollection services)
        {
            services.AddOcelot();
            services.AddAuthentication()
                .AddIdentityServerAuthentication(authenticationProviderKey, WithOptions);
        }
        GivenOcelotIsRunning(WithIdentityServerAuthentication);
    }
}
