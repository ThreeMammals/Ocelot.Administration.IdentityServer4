using CacheManager.Core;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Ocelot.Cache.CacheManager;
using Ocelot.Configuration.File;
using Ocelot.DependencyInjection;
using System.Security.Policy;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public sealed class CacheManagerTests : IdentityServerSteps
{
    public CacheManagerTests() : base()
    {
    }

    /// <summary>
    /// TODO Unstable test because of System.AggregateException:
    /// One or more errors occurred. (The process cannot access the file '..\Ocelot.Administration.IdentityServer4\acceptance\bin\Debug\net9.0\ocelot.Production.json' because it is being used by another process.)
    /// </summary>
    [Fact]
    public async Task ShouldClearRegionViaAdministrationAPI()
    {
        int port = PortFinder.GetRandomPort();
        var ocelotUrl = DownstreamUrl(port);
        var configuration = new FileConfiguration
        {
            Routes = [
                GivenRoute(),
                GivenRoute("/test"),
            ],
            GlobalConfiguration = new()
            {
                BaseUrl = ocelotUrl,
            },
        };
        GivenThereIsAConfiguration(configuration);

        using var ocelot = await GivenOcelotHostIsRunning
        (
            WithBasicConfiguration, WithCacheManager, WithUseOcelot,
            (host) => host.UseUrls(ocelotUrl)
        );
        ocelotClient = new()
        {
            BaseAddress = new(ocelotUrl),
        };
        await GivenIHaveAnOcelotToken("/administration"); // TODO Move to AuthSteps
        GivenIHaveAddedATokenToMyRequest();

        await WhenIDeleteUrlOnTheApiGateway($"/administration/outputcache/{nameof(ShouldClearRegionViaAdministrationAPI)}");

        ThenTheStatusCodeShouldBe(HttpStatusCode.NoContent);
    }

    public static FileCacheOptions DefaultFileCacheOptions { get; set; } = new()
    {
        TtlSeconds = 10,
    };

    private static FileRoute GivenRoute(string? upstream = null, FileCacheOptions? options = null) => new()
    {
        DownstreamHostAndPorts =
        [
            new("localhost", 80),
        ],
        DownstreamScheme = Uri.UriSchemeHttps,
        DownstreamPathTemplate = "/",
        UpstreamHttpMethod = [HttpMethods.Get],
        UpstreamPathTemplate = upstream ?? "/",
        FileCacheOptions = options ?? DefaultFileCacheOptions,
    };

    private async Task GivenIHaveAnOcelotToken(string adminPath)
    {
        var formData = new List<KeyValuePair<string, string>>
        {
            new("client_id", "admin"),
            new("client_secret", "secret"),
            new("scope", "admin"),
            new("grant_type", "client_credentials"),
        };
        await GivenIHaveATokenWithForm(adminPath, formData, ocelotClient); // TODO Steps but move to AuthSteps
        //var response = await _ocelotClient.GetAsync($"{adminPath}/.well-known/openid-configuration");
        //response.EnsureSuccessStatusCode();
        await VerifyIdentityServerStarted(adminPath, ocelotClient);
    }

    private static void WithCacheManager(IServiceCollection services)
    {
        static void WithSettings(ConfigurationBuilderCachePart settings)
        {
            settings.WithDictionaryHandle();
        }
        services.AddMvc(option => option.EnableEndpointRouting = false);
        services.AddOcelot()
            .AddCacheManager(WithSettings)
            .AddAdministration("/administration", "secret");
    }

    public override void Dispose()
    {
        Environment.SetEnvironmentVariable(IdentityServerConfigurationCreator.OCELOT_CERTIFICATE, string.Empty);
        Environment.SetEnvironmentVariable(IdentityServerConfigurationCreator.OCELOT_CERTIFICATE_PASSWORD, string.Empty);
        base.Dispose();
    }
}
