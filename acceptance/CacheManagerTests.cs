using CacheManager.Core;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Ocelot.Cache.CacheManager;
using Ocelot.Configuration.File;
using Ocelot.DependencyInjection;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public sealed class CacheManagerTests : Steps
{
    public CacheManagerTests() : base()
    {
    }

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
        _ocelotClient = new()
        {
            BaseAddress = new(ocelotUrl),
        };

        await GivenIHaveAnOcelotToken("/administration"); // TODO Move to AuthSteps
        GivenIHaveAddedATokenToMyRequest();

        _response = await _ocelotClient.DeleteAsync($"/administration/outputcache/{nameof(ShouldClearRegionViaAdministrationAPI)}");

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
        await GivenIHaveATokenWithForm(adminPath, formData, _ocelotClient); // TODO Steps but move to AuthSteps
        var response = await _ocelotClient.GetAsync($"{adminPath}/.well-known/openid-configuration");
        response.EnsureSuccessStatusCode();
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
        Environment.SetEnvironmentVariable("OCELOT_CERTIFICATE", string.Empty);
        Environment.SetEnvironmentVariable("OCELOT_CERTIFICATE_PASSWORD", string.Empty);
        base.Dispose();
    }
}
