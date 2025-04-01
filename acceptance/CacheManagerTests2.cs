using CacheManager.Core;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;
using Ocelot.Cache.CacheManager;
using Ocelot.Configuration.File;
using Ocelot.DependencyInjection;
using Ocelot.DownstreamUrlCreator.Middleware;
using Ocelot.Middleware;
using System;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Security.Policy;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public sealed class CacheManagerTests2 : Steps
{
    //private readonly HttpClient _httpClient;
    //private readonly HttpClient _httpClientTwo;
    //private HttpResponseMessage _response;
    //private IHost _builder;
    //private IHostBuilder _hostBuilder;
    //private readonly string _ocelotUrl;
    //private BearerToken _token;

    public CacheManagerTests2()
    {
        //_httpClient = new HttpClient();
        //_httpClientTwo = new HttpClient();
        ////_ocelotUrl = "http://localhost:5000";
        //_httpClient.BaseAddress = new Uri(_ocelotUrl);
    }

    [Fact(Skip = "https://github.com/ThreeMammals/Ocelot/pull/1025/files#diff-bda37725895a95e577429be88c614803fb0ca66fada3daaa204d41bd2ca1dc30")]
    public async Task ShouldClearRegion()
    {
        int port = 5000; //PortFinder.GetRandomPort();
        var ocelotUrl = DownstreamUrl(port);
        var configuration = new FileConfiguration
        {
            Routes = new()
            {
                GivenRoute(),
                GivenRoute("/test"),
            },
            GlobalConfiguration = new()
            {
                BaseUrl = ocelotUrl,
            },
        };
        var regionToClear = "gettest";
        GivenThereIsAConfiguration(configuration);

        GivenOcelotIsRunning(WithBasicConfiguration, WithCacheManager, WithUseOcelot,
            (host) => host.UseUrls(ocelotUrl)
                    .UseKestrel()
                    .UseContentRoot(Directory.GetCurrentDirectory())
                    .Configure(async app => await app.UseOcelot()),
            (client) => client.BaseAddress = new(ocelotUrl)); // BaseAddress must be updated in Steps of the main testing project to support parallelism

        await GivenIHaveAnOcelotToken("/administration");
        GivenIHaveAddedATokenToMyRequest();

        //await WhenIDeleteOnTheApiGateway($"/administration/outputcache/{regionToClear}");
        _response = await _ocelotClient.DeleteAsync($"/administration/outputcache/{regionToClear}");

        ThenTheStatusCodeShouldBe(HttpStatusCode.NoContent);
    }

    //private void GivenOcelotIsRunningWithAdministration(
    //    Action<WebHostBuilderContext, IConfigurationBuilder>? configureDelegate,
    //    Action<IServiceCollection>? configureServices,
    //    Action<IApplicationBuilder>? configureApp,
    //    Action<IWebHostBuilder>? configureHost,
    //    Action<HttpClient>? configureClient)
    //{
    //    _hostBuilder = TestHostBuilder.Create() // ValidateScopes = true
    //        .ConfigureAppConfiguration(configureDelegate ?? WithBasicConfiguration)
    //        .ConfigureServices(configureServices ?? WithAddOcelot)
    //        .Configure(configureApp ?? WithUseOcelot);

    //    configureHost?.Invoke(_hostBuilder);
    //    _ocelotServer = new TestServer(_hostBuilder);
    //    _ocelotClient = _ocelotServer.CreateClient();
    //    configureClient?.Invoke(_ocelotClient);
    //}

    public static FileCacheOptions DefaultFileCacheOptions { get; set; } = new()
    {
        TtlSeconds = 10,
    };

    private FileRoute GivenRoute(string? upstream = null, FileCacheOptions? options = null) => new()
    {
        DownstreamHostAndPorts = new()
        {
            new("localhost", 80),
        },
        DownstreamScheme = Uri.UriSchemeHttps,
        DownstreamPathTemplate = "/",
        UpstreamHttpMethod = new() { HttpMethods.Get },
        UpstreamPathTemplate = upstream ?? "/",
        FileCacheOptions = options ?? DefaultFileCacheOptions,
    };

    //private void GivenIHaveAddedATokenToAuthorization()
    //{
    //    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _token.AccessToken);
    //}

    private async Task GivenIHaveAnOcelotToken(string adminPath)
    {
        //var tokenUrl = $"{adminPath}/connect/token";
        var formData = new List<KeyValuePair<string, string>>
        {
            new("client_id", "admin"),
            new("client_secret", "secret"),
            new("scope", "admin"),
            new("grant_type", "client_credentials"),
        };
        //var content = new FormUrlEncodedContent(formData);
        //var response = await _httpClient.PostAsync(tokenUrl, content);
        //var responseContent = await response.Content.ReadAsStringAsync();
        //response.EnsureSuccessStatusCode();
        //_token = JsonConvert.DeserializeObject<BearerToken>(responseContent);
        await GivenIHaveATokenWithForm(adminPath, formData, _ocelotClient); // Steps

        //using var http = new HttpClient();
        var response = await _ocelotClient.GetAsync($"{adminPath}/.well-known/openid-configuration");
        response.EnsureSuccessStatusCode();
    }

    private static void WithCacheManager(IServiceCollection services)
    {
        Action<ConfigurationBuilderCachePart> settings = (s) =>
        {
            s.WithMicrosoftLogging(log =>
            {
                //log.AddConsole(LogLevel.Debug);
            })
            .WithDictionaryHandle();
        };
        services.AddMvc(option => option.EnableEndpointRouting = false);
        services.AddOcelot()
            .AddCacheManager(settings)
            .AddAdministration("/administration", "secret");
    }

    //private void GivenOcelotIsRunningInternal()
    //{
    //    _hostBuilder = Host.CreateDefaultBuilder()
    //        .ConfigureAppConfiguration((hostingContext, config) =>
    //        {
    //            config.SetBasePath(hostingContext.HostingEnvironment.ContentRootPath);
    //            var env = hostingContext.HostingEnvironment;
    //            config.AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
    //            .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true, reloadOnChange: false);
    //            config.AddJsonFile("ocelot.json", false, false);
    //            config.AddEnvironmentVariables();
    //        })
    //        .ConfigureServices(x =>
    //        {
    //            Action<ConfigurationBuilderCachePart> settings = (s) =>
    //            {
    //                s.WithMicrosoftLogging(log =>
    //                {
    //                    //log.AddConsole(LogLevel.Debug);
    //                })
    //                .WithDictionaryHandle();
    //            };
    //            x.AddMvc(option => option.EnableEndpointRouting = false);
    //            x.AddOcelot()
    //            .AddCacheManager(settings)
    //            .AddAdministration("/administration", "secret");
    //        })
    //        .ConfigureWebHost(webBuilder =>
    //    {
    //        webBuilder.UseUrls(_ocelotUrl)
    //        .UseKestrel()
    //        .UseContentRoot(Directory.GetCurrentDirectory())
    //        .Configure(async app => await app.UseOcelot());
    //    });

    //    _builder = _hostBuilder.Build();
    //    _builder.Start();
    //}

    //private static void GivenThereIsAConfiguration(FileConfiguration fileConfiguration)
    //{
    //    // TODO: Turn method as async
    //    var configurationPath = $"{Directory.GetCurrentDirectory()}/ocelot.json";

    //    var jsonConfiguration = JsonConvert.SerializeObject(fileConfiguration);

    //    if (File.Exists(configurationPath))
    //    {
    //        File.Delete(configurationPath);
    //    }

    //    File.WriteAllText(configurationPath, jsonConfiguration);

    //    var text = File.ReadAllText(configurationPath);

    //    configurationPath = $"{AppContext.BaseDirectory}/ocelot.json";

    //    if (File.Exists(configurationPath))
    //    {
    //        File.Delete(configurationPath);
    //    }

    //    File.WriteAllText(configurationPath, jsonConfiguration);

    //    text = File.ReadAllText(configurationPath);
    //}

    //private async Task WhenIDeleteOnTheApiGateway(string url)
    //{
    //    _response = await _ocelotClient.DeleteAsync(url);
    //}

    //private void ThenTheStatusCodeShouldBe(HttpStatusCode expectedHttpStatusCode)
    //{
    //    _response.StatusCode.ShouldBe(expectedHttpStatusCode);
    //}

    public override void Dispose()
    {
        Environment.SetEnvironmentVariable("OCELOT_CERTIFICATE", string.Empty);
        Environment.SetEnvironmentVariable("OCELOT_CERTIFICATE_PASSWORD", string.Empty);
        //_builder?.Dispose();
        //_httpClient?.Dispose();
        base.Dispose();
    }
}
