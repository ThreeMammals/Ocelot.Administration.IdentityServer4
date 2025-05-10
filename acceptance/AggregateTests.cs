using IdentityServer4.AccessTokenValidation;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Ocelot.Configuration.File;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public sealed class AggregateTests : IdentityServerSteps
{
    private readonly string[] _downstreamPaths;

    public AggregateTests()
    {
        _downstreamPaths = new string[3];
    }

    [Fact]
    [Trait("Bug", "1396")]
    public async Task Should_return_response_200_with_user_forwarding()
    {
        const string Api_Name = "api";
        var port1 = PortFinder.GetRandomPort();
        var port2 = PortFinder.GetRandomPort();
        var port3 = PortFinder.GetRandomPort();
        var route1 = GivenRoute(port1, "/laura", "Laura");
        var route2 = GivenRoute(port2, "/tom", "Tom");
        var configuration = GivenConfiguration(route1, route2);
        var identityServerUrl = DownstreamUrl(port3);
        void ConfigureOptions(IdentityServerAuthenticationOptions o)
        {
            o.Authority = identityServerUrl;
            o.ApiName = Api_Name;
            o.RequireHttpsMetadata = false;
            o.SupportedTokens = SupportedTokens.Both;
            o.ApiSecret = "secret";
            o.ForwardDefault = IdentityServerAuthenticationDefaults.AuthenticationScheme;
        }
        void ConfigureServices(IServiceCollection s)
        {
            s.AddOcelot();
            s.AddMvcCore(mvc =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .RequireClaim("scope", Api_Name)
                    .Build();
                mvc.Filters.Add(new AuthorizeFilter(policy));
            });
            s.AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
                .AddIdentityServerAuthentication(ConfigureOptions);
        }
        var count = 0;
        var actualContexts = new HttpContext[2];
        async void ConfigureAppPipeline(IApplicationBuilder app)
        {
            var configuration = new OcelotPipelineConfiguration
            {
                PreErrorResponderMiddleware = async (context, next) =>
                {
                    var auth = await context.AuthenticateAsync();
                    context.User = (auth.Succeeded && auth.Principal?.IsAuthenticated() == true) ? auth.Principal : null!;
                    await next.Invoke();
                },
                AuthorizationMiddleware = (context, next) =>
                {
                    actualContexts[count++] = context;
                    return next.Invoke();
                },
            };
            await app.UseOcelot(configuration);
        }
        //await GivenThereIsAnIdentityServerOn(identityServerUrl, AccessTokenType.Jwt);
        await GivenThereIsAnIdentityServerOn(identityServerUrl, Api_Name);
        GivenServiceIsRunning(0, port1, "/", 200, "{Hello from Laura}");
        GivenServiceIsRunning(1, port2, "/", 200, "{Hello from Tom}");
        await GivenIHaveAToken(identityServerUrl);
        GivenThereIsAConfiguration(configuration);
        GivenOcelotIsRunning(null!, ConfigureServices, ConfigureAppPipeline);
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        ThenTheResponseBodyShouldBe("{\"Laura\":{Hello from Laura},\"Tom\":{Hello from Tom}}");
        ThenTheDownstreamUrlPathShouldBe("/", "/");

        // Assert
        for (var i = 0; i < actualContexts.Length; i++)
        {
            var ctx = actualContexts[i].ShouldNotBeNull();
            ctx.Items.DownstreamRoute().Key.ShouldBe(configuration.Routes[i].Key);
            var user = ctx.User.ShouldNotBeNull();
            user.IsAuthenticated().ShouldBeTrue();
            user.Claims.Count().ShouldBeGreaterThan(1);
            user.Claims.FirstOrDefault(c => c is { Type: "scope", Value: "api" }).ShouldNotBeNull();
        }
    }

    private void GivenServiceIsRunning(int index, int port, string basePath, int statusCode, string responseBody)
        => GivenServiceIsRunning(index, port, basePath, statusCode,
            async context =>
            {
                await context.Response.WriteAsync(responseBody);
            });

    private void GivenServiceIsRunning(int index, int port, string basePath, int statusCode, Action<HttpContext> processContext)
    {
        var baseUrl = DownstreamUrl(port);
        handler.GivenThereIsAServiceRunningOn(baseUrl, basePath, async context =>
        {
            _downstreamPaths[index] = !string.IsNullOrEmpty(context.Request.PathBase.Value)
                ? context.Request.PathBase.Value
                : context.Request.Path.Value!;

            if (_downstreamPaths[index] != basePath)
            {
                context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                await context.Response.WriteAsync($"Downstream path with index {index} doesn't match base path");
            }
            else
            {
                context.Response.StatusCode = statusCode;
                processContext?.Invoke(context);
            }
        });
    }

    private void ThenTheDownstreamUrlPathShouldBe(string expectedDownstreamPathOne, string expectedDownstreamPath)
    {
        _downstreamPaths[0].ShouldBe(expectedDownstreamPathOne);
        _downstreamPaths[1].ShouldBe(expectedDownstreamPath);
    }

    private static FileRoute GivenRoute(int port, string upstream, string key, string? downstream = null) => new()
    {
        DownstreamPathTemplate = downstream ?? "/",
        DownstreamScheme = Uri.UriSchemeHttp,
        DownstreamHostAndPorts = [ Localhost(port) ],
        UpstreamPathTemplate = upstream,
        UpstreamHttpMethod = [ HttpMethods.Get ],
        Key = key,
    };

    protected override FileConfiguration GivenConfiguration(params FileRoute[] routes)
    {
        var con = base.GivenConfiguration(routes);
        con.Aggregates.Add(new()
        {
            UpstreamPathTemplate = "/",
            UpstreamHost = "localhost",
            RouteKeys = [.. routes.Select(r => r.Key)], // [ "Laura", "Tom" ],
        });
        return con;
    }
}
