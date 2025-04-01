using IdentityServer4.AccessTokenValidation;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Ocelot.Configuration.File;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using Ocelot.Multiplexer;
using System.Text;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public sealed class AggregateTests : Steps, IDisposable
{
    private readonly ServiceHandler _serviceHandler;
    private readonly string[] _downstreamPaths;

    public AggregateTests()
    {
        _serviceHandler = new ServiceHandler();
        _downstreamPaths = new string[3];
    }

    public override void Dispose()
    {
        _serviceHandler.Dispose();
        base.Dispose();
    }

    [Fact]
    [Trait("Bug", "1396")]
    public void Should_return_response_200_with_user_forwarding()
    {
        var port1 = PortFinder.GetRandomPort();
        var port2 = PortFinder.GetRandomPort();
        var port3 = PortFinder.GetRandomPort();
        var route1 = GivenRoute(port1, "/laura", "Laura");
        var route2 = GivenRoute(port2, "/tom", "Tom");
        var configuration = GivenConfiguration(route1, route2);
        var identityServerUrl = $"{Uri.UriSchemeHttp}://localhost:{port3}";
        void configureOptions(IdentityServerAuthenticationOptions o)
        {
            o.Authority = identityServerUrl;
            o.ApiName = "api";
            o.RequireHttpsMetadata = false;
            o.SupportedTokens = SupportedTokens.Both;
            o.ApiSecret = "secret";
            o.ForwardDefault = IdentityServerAuthenticationDefaults.AuthenticationScheme;
        }
        Action<IServiceCollection> configureServices = s =>
        {
            s.AddOcelot();
            s.AddMvcCore(mvc =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .RequireClaim("scope", "api")
                    .Build();
                mvc.Filters.Add(new AuthorizeFilter(policy));
            });
            s.AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
                .AddIdentityServerAuthentication(configureOptions);
        };
        var count = 0;
        var actualContexts = new HttpContext[2];
        Action<IApplicationBuilder> configureApp = async (app) =>
        {
            var configuration = new OcelotPipelineConfiguration
            {
                PreErrorResponderMiddleware = async (context, next) =>
                {
                    var auth = await context.AuthenticateAsync();
                    context.User = (auth.Succeeded && auth.Principal?.IsAuthenticated() == true)
                        ? auth.Principal : null;
                    await next.Invoke();
                },
                AuthorizationMiddleware = (context, next) =>
                {
                    actualContexts[count++] = context;
                    return next.Invoke();
                },
            };
            await app.UseOcelot(configuration);
        };
        using (var auth = new AuthenticationTests())
        {
            this.Given(x => auth.GivenThereIsAnIdentityServerOn(identityServerUrl, AccessTokenType.Jwt))
                .And(x => x.GivenServiceIsRunning(0, port1, "/", 200, "{Hello from Laura}"))
                .And(x => x.GivenServiceIsRunning(1, port2, "/", 200, "{Hello from Tom}"))
                .And(x => auth.GivenIHaveAToken(identityServerUrl))
                .And(x => auth.GivenThereIsAConfiguration(configuration))
                .And(x => auth.GivenOcelotIsRunningWithServices(configureServices, configureApp))
                .And(x => auth.GivenIHaveAddedATokenToMyRequest())
                .When(x => auth.WhenIGetUrlOnTheApiGateway("/"))
                .Then(x => auth.ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
                .And(x => auth.ThenTheResponseBodyShouldBe("{\"Laura\":{Hello from Laura},\"Tom\":{Hello from Tom}}"))
                .And(x => x.ThenTheDownstreamUrlPathShouldBe("/", "/"))
                .BDDfy();
        }

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

    private static string FormatFormCollection(IFormCollection reqForm)
    {
        var sb = new StringBuilder()
            .Append('"');

        foreach (var kvp in reqForm)
        {
            sb.Append($"[{kvp.Key}:{kvp.Value}]");
        }

        return sb
            .Append('"')
            .ToString();
    }

    private void GivenServiceIsRunning(string baseUrl, int statusCode, string responseBody)
    {
        _serviceHandler.GivenThereIsAServiceRunningOn(baseUrl, async context =>
        {
            context.Response.StatusCode = statusCode;
            await context.Response.WriteAsync(responseBody);
        });
    }

    private void GivenServiceIsRunning(int index, int port, string basePath, int statusCode, string responseBody)
        => GivenServiceIsRunning(index, port, basePath, statusCode,
            async context =>
            {
                await context.Response.WriteAsync(responseBody);
            });

    private void GivenServiceIsRunning(int index, int port, string basePath, int statusCode, Func<string, string> responseFromBody)
        => GivenServiceIsRunning(index, port, basePath, statusCode,
            async context =>
            {
                var requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
                var responseBody = responseFromBody(requestBody);
                await context.Response.WriteAsync(responseBody);
            });

    private void GivenServiceIsRunning(int index, int port, string basePath, int statusCode, Func<IFormCollection, string> responseFromForm)
        => GivenServiceIsRunning(index, port, basePath, statusCode,
            async context =>
            {
                var responseBody = responseFromForm(context.Request.Form);
                await context.Response.WriteAsync(responseBody);
            });

    private void GivenServiceIsRunning(int index, int port, string basePath, int statusCode, Action<HttpContext> processContext)
    {
        var baseUrl = DownstreamUrl(port);
        _serviceHandler.GivenThereIsAServiceRunningOn(baseUrl, basePath, async context =>
        {
            _downstreamPaths[index] = !string.IsNullOrEmpty(context.Request.PathBase.Value)
                ? context.Request.PathBase.Value
                : context.Request.Path.Value;

            if (_downstreamPaths[index] != basePath)
            {
                context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                await context.Response.WriteAsync("downstream path doesn't match base path");
            }
            else
            {
                context.Response.StatusCode = statusCode;
                processContext?.Invoke(context);
            }
        });
    }

    private void GivenOcelotIsRunningWithSpecificAggregatorsRegisteredInDi<TAggregator, TDependency>()
        where TAggregator : class, IDefinedAggregator
        where TDependency : class
    {
        _webHostBuilder = TestHostBuilder.Create()
            .ConfigureAppConfiguration((hostingContext, config) =>
            {
                config.SetBasePath(hostingContext.HostingEnvironment.ContentRootPath);
                var env = hostingContext.HostingEnvironment;
                config.AddJsonFile("appsettings.json", true, false)
                    .AddJsonFile($"appsettings.{env.EnvironmentName}.json", true, false);
                config.AddJsonFile(_ocelotConfigFileName, true, false);
                config.AddEnvironmentVariables();
            })
            .ConfigureServices(s =>
            {
                s.AddSingleton(_webHostBuilder);
                s.AddSingleton<TDependency>();
                s.AddOcelot()
                    .AddSingletonDefinedAggregator<TAggregator>();
            })
            .Configure(async b => await b.UseOcelot());

        _ocelotServer = new TestServer(_webHostBuilder);
        _ocelotClient = _ocelotServer.CreateClient();
    }

    private void ThenTheDownstreamUrlPathShouldBe(string expectedDownstreamPathOne, string expectedDownstreamPath)
    {
        _downstreamPaths[0].ShouldBe(expectedDownstreamPathOne);
        _downstreamPaths[1].ShouldBe(expectedDownstreamPath);
    }

    private static FileRoute GivenRoute(int port, string upstream, string key, string downstream = null) => new()
    {
        DownstreamPathTemplate = downstream ?? "/",
        DownstreamScheme = Uri.UriSchemeHttp,
        DownstreamHostAndPorts = new() { new("localhost", port) },
        UpstreamPathTemplate = upstream,
        UpstreamHttpMethod = new() { HttpMethods.Get },
        Key = key,
    };

    private static new FileConfiguration GivenConfiguration(params FileRoute[] routes)
    {
        var obj = Steps.GivenConfiguration(routes);
        obj.Aggregates.Add(
            new()
            {
                UpstreamPathTemplate = "/",
                UpstreamHost = "localhost",
                RouteKeys = routes.Select(r => r.Key).ToList(), // [ "Laura", "Tom" ],
            }
        );
        return obj;
    }
}

public class FakeDep
{
}

public class FakeDefinedAggregator : IDefinedAggregator
{
    public FakeDefinedAggregator(FakeDep dep)
    {
    }

    public async Task<DownstreamResponse> Aggregate(List<HttpContext> responses)
    {
        var one = await responses[0].Items.DownstreamResponse().Content.ReadAsStringAsync();
        var two = await responses[1].Items.DownstreamResponse().Content.ReadAsStringAsync();

        var merge = $"{one}, {two}";
        merge = merge.Replace("Hello", "Bye").Replace("{", "").Replace("}", "");
        var headers = responses.SelectMany(x => x.Items.DownstreamResponse().Headers).ToList();
        return new DownstreamResponse(new StringContent(merge), HttpStatusCode.OK, headers, "some reason");
    }
}
