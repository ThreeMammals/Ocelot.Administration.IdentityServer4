using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;
using Ocelot.Configuration.ChangeTracking;
using Ocelot.Configuration.File;
using Ocelot.DependencyInjection;
using System.Reflection;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public sealed class AdministrationTests : IdentityServerSteps
{
    public AdministrationTests() : base()
    { }

    [Fact]
    public async Task Should_return_response_401_with_call_re_routes_controller()
    {
        int port = PortFinder.GetRandomPort();
        var url = DownstreamUrl(port);
        var configuration = GivenConfiguration(url);
        GivenThereIsAConfiguration(configuration);

        using var ocelot = await GivenOcelotIsRunningWithAdministration(url);
        await WhenIGetUrlOnTheApiGateway("/administration/configuration");
        ThenTheStatusCodeShouldBe(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// Oc-Feat: <see href="https://github.com/ThreeMammals/Ocelot/issues/228">#228</see>
    /// <para>Oc-PR: <see href="https://github.com/ThreeMammals/Ocelot/pull/232">#232</see></para>
    /// <para>This seems to be be answer: <see href="https://github.com/DuendeArchive/IdentityServer4/issues/4914">IS4 #4914</see></para>
    /// </summary>
    [Fact]
    [Trait("OcFeat", "228")]
    [Trait("OcPull", "232")]
    public async Task Should_return_response_200_with_call_re_routes_controller()
    {
        int port = PortFinder.GetRandomPort();
        var ocelotBaseUrl = DownstreamUrl(port);
        var configuration = GivenConfiguration(ocelotBaseUrl); // BaseUrl
        GivenThereIsAConfiguration(configuration);

        using var ocelot = await GivenOcelotIsRunningWithNoWebHostBuilder(ocelotBaseUrl); // TestHostBuilder.CreateHost() -> Host.CreateDefaultBuilder()
        await GivenIHaveAnOcelotToken("/administration");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/administration/configuration");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
    }

    /// <summary>
    /// Oc-Feat: <see href="https://github.com/ThreeMammals/Ocelot/issues/233">#233</see>
    /// <para>Oc-PR: <see href="https://github.com/ThreeMammals/Ocelot/pull/234">#234</see></para>
    /// </summary>
    [Fact]
    [Trait("OcFeat", "233")]
    [Trait("OcPull", "234")]
    public async Task Should_return_response_200_with_call_routes_controller_using_base_url_added_in_file_config()
    {
        int port = PortFinder.GetRandomPort();
        var url = DownstreamUrl(port);
        var configuration = GivenConfiguration(url); // !!! BaseUrl
        GivenThereIsAConfiguration(configuration);

        using var ocelot = await GivenOcelotIsRunningWithNoWebHostBuilder(url);
        await GivenIHaveAnOcelotToken("/administration");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/administration/configuration");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
    }

    /// <summary>Oc PR: <see href="https://github.com/ThreeMammals/Ocelot/pull/1655">#1655</see></summary>
    [Fact, Trait("OcPull", "1655")]
    public async Task Should_return_OK_status_and_multiline_indented_json_response_with_json_options_for_custom_builder()
    {
        int port = PortFinder.GetRandomPort();
        var url = DownstreamUrl(port);
        var configuration = GivenConfiguration(url); // !!! BaseUrl
        GivenThereIsAConfiguration(configuration);
        static IMvcCoreBuilder CustomBuilder(IMvcCoreBuilder builder, Assembly assembly) => builder
            .AddApplicationPart(assembly)
            .AddControllersAsServices()
            .AddAuthorization()
            .AddJsonOptions(options => { options.JsonSerializerOptions.WriteIndented = true; });
        using var ocelot = await GivenOcelotUsingBuilderIsRunning(url, CustomBuilder);
        await GivenIHaveAnOcelotToken("/administration");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/administration/configuration");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        await ThenTheResultHaveMultiLineIndentedJson();
    }

    // .NET 9 has breaking changes related to JwtSecurityToken.
    // More info: https://learn.microsoft.com/en-us/dotnet/core/compatibility/aspnet-core/8.0/securitytoken-events
#if NET9_0_OR_GREATER
#pragma warning disable IDE0079 // Remove unnecessary suppression
#pragma warning disable xUnit1004 // Test methods should not be skipped
    [Fact(Skip = "Require migration to .NET 9 or disabling.")]
#pragma warning restore xUnit1004 // Test methods should not be skipped
#pragma warning restore IDE0079 // Remove unnecessary suppression
#else
    [Fact]
#endif
    public async Task Should_be_able_to_use_token_from_OcelotA_on_OcelotB()
    {
        int port = PortFinder.GetRandomPort();
        var url = DownstreamUrl(port);
        var configuration = GivenConfiguration(url); // !!! BaseUrl
        GivenThereIsAConfiguration(configuration);
        GivenIdentityServerSigningEnvironmentalVariablesAreSet();

        using var ocelot = await GivenOcelotIsRunningWithAdministration(url);
        await GivenIHaveAnOcelotToken("/administration");
        int port2 = PortFinder.GetRandomPort();
        var url2 = DownstreamUrl(port2);
        var configuration2 = GivenConfiguration(url2); // !!! BaseUrl
        GivenThereIsAConfiguration(configuration2);
        var ocelot2ConfigFileName = $"{ocelotConfigFileName.Split("-")[0]}_2nd-{ConfigurationBuilderExtensions.PrimaryConfigFile}";
        GivenThereIsAConfiguration(configuration2, ocelot2ConfigFileName);

        var (ocelot2, client) = await GivenAnotherOcelotIsRunning(url2, ocelot2ConfigFileName);
        using var oc = ocelot2;
        using var cl = client;
        await WhenIGetUrlOnTheSecondOcelot(cl, "/administration/configuration");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        await oc.StopAsync();
    }

    [Fact]
    public async Task Should_return_file_configuration()
    {
        int ocPort = PortFinder.GetRandomPort();
        var ocUrl = DownstreamUrl(ocPort);
        var route1 = GivenRoute(PortFinder.GetRandomPort(),
            cacheOptions: new() { TtlSeconds = 10, Region = "Geoff" });
        var route2 = GivenRoute(PortFinder.GetRandomPort(),
            upstream: "/test",
            cacheOptions: new() { TtlSeconds = 10, Region = "Dave" });

        var configuration = GivenConfiguration(route1, route2);
        configuration.GlobalConfiguration = new()
        {
            BaseUrl = ocUrl,
            RequestIdKey = "RequestId",
            ServiceDiscoveryProvider = new()
            {
                Scheme = "https",
                Host = "127.0.0.1",
            },
        };
        GivenThereIsAConfiguration(configuration);

        using var ocelot = await GivenOcelotIsRunningWithAdministration(ocUrl);
        await GivenIHaveAnOcelotToken("/administration");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/administration/configuration");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        await ThenTheResponseShouldBe(configuration);
    }

    /// <summary>Oc-Bug: <see href="https://github.com/ThreeMammals/Ocelot/issues/463">#463</see></summary>
    [Fact]
    [Trait("OcBug", "463")]
    public async Task Should_get_file_configuration_edit_and_post_updated_version()
    {
        int ocPort = PortFinder.GetRandomPort();
        var ocUrl = DownstreamUrl(ocPort);
        var route1 = GivenRoute(PortFinder.GetRandomPort());
        var route2 = GivenRoute(PortFinder.GetRandomPort(), "/test");
        var initialConfiguration = GivenConfiguration(ocUrl, route1, route2);

        var route_1 = GivenRoute(PortFinder.GetRandomPort(), "/", "/geoffrey");
        var route_2 = GivenRoute(PortFinder.GetRandomPort(), "/test/{productId}", "/blooper/{productId}");
        var updatedConfiguration = GivenConfiguration(ocUrl, route_1, route_2);
        GivenThereIsAConfiguration(initialConfiguration);

        using var ocelot = await GivenOcelotIsRunningWithAdministration(ocUrl);
        await GivenIHaveAnOcelotToken("/administration");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/administration/configuration");
        await WhenIPostOnTheApiGateway("/administration/configuration", updatedConfiguration);
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        await ThenTheResponseShouldBe(updatedConfiguration);
        await WhenIGetUrlOnTheApiGateway("/administration/configuration");
        await ThenTheResponseShouldBe(updatedConfiguration);
        ThenTheConfigurationIsSavedCorrectly(updatedConfiguration); // OcBug 463
    }

    /// <summary>
    /// Oc-Feat: <see href="https://github.com/ThreeMammals/Ocelot/issues/1036">#1036</see>
    /// <para>Oc-PR: <see href="https://github.com/ThreeMammals/Ocelot/pull/1037">#1037</see></para>
    /// <para>Oc-PR: <see href="https://github.com/ThreeMammals/Ocelot/pull/1122">#1122</see></para>
    /// </summary>
    [Fact]
    [Trait("OcFeat", "1036")]
    [Trait("OcPull", "1037 1122")]
    public async Task Should_activate_change_token_when_configuration_is_updated()
    {
        int ocPort = PortFinder.GetRandomPort();
        var ocUrl = DownstreamUrl(ocPort);
        var route = GivenRoute(PortFinder.GetRandomPort());
        var configuration = GivenConfiguration(ocUrl, route);
        GivenThereIsAConfiguration(configuration);

        using var ocelot = await GivenOcelotIsRunningWithAdministration(ocUrl);
        await GivenIHaveAnOcelotToken("/administration");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIPostOnTheApiGateway("/administration/configuration", configuration);
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        TheChangeTokenShouldBeActive(ocelot);
        await ThenTheResponseShouldBe(configuration);
        await WhenIGetUrlOnTheApiGateway("/administration/configuration");
        await ThenTheResponseShouldBe(configuration);
        ThenTheConfigurationIsSavedCorrectly(configuration);
    }

    private static void TheChangeTokenShouldBeActive(IHost ocelot) => ocelot
        .Services.GetRequiredService<IOcelotConfigurationChangeTokenSource>().ShouldNotBeNull()
        .ChangeToken.HasChanged.ShouldBeTrue();

    /// <summary>
    /// Added in the fix of Oc-Bug <see href="https://github.com/ThreeMammals/Ocelot/issues/463">#463</see> and Oc-PR <see href="https://github.com/ThreeMammals/Ocelot/pull/506">#506</see>.
    /// </summary>
    private static void ThenTheConfigurationIsSavedCorrectly(FileConfiguration expected)
    {
        var ocelotJsonPath = $"{AppContext.BaseDirectory}ocelot.json";
        var resultText = File.ReadAllText(ocelotJsonPath);
        var expectedText = JsonConvert.SerializeObject(expected, Formatting.Indented);
        resultText.ShouldBe(expectedText);

        var environmentSpecificPath = $"{AppContext.BaseDirectory}/ocelot.Production.json";
        resultText = File.ReadAllText(environmentSpecificPath);
        expectedText = JsonConvert.SerializeObject(expected, Formatting.Indented);
        resultText.ShouldBe(expectedText);
    }

    /// <summary>
    /// Oc-Bug: <see href="https://github.com/ThreeMammals/Ocelot/issues/383">#383</see>
    /// <para>Oc-PR: <see href="https://github.com/ThreeMammals/Ocelot/pull/421">#421</see></para>
    /// </summary>
    [Fact]
    [Trait("OcBug", "383")]
    [Trait("OcPull","421")]
    public async Task Should_get_file_configuration_edit_and_post_updated_version_redirecting_route()
    {
        int ocPort = PortFinder.GetRandomPort();
        var ocUrl = DownstreamUrl(ocPort);
        var fooPort = PortFinder.GetRandomPort();
        var barPort = PortFinder.GetRandomPort();
        var route = GivenRoute(fooPort, "/foo", "/foo");
        var initialConfiguration = GivenConfiguration(ocUrl, route);
        var route2 = GivenRoute(barPort, "/foo", "/bar");
        var updatedConfiguration = GivenConfiguration(ocUrl, route2);
        GivenThereIsAConfiguration(initialConfiguration);
        GivenThereIsAServiceRunningOn(fooPort, "/foo");
        GivenThereIsAServiceRunningOn(barPort, "/bar");

        using var ocelot = await GivenOcelotIsRunningWithAdministration(ocUrl);
        await WhenIGetUrlOnTheApiGateway("/foo");
        ThenTheResponseBodyShouldBe("/foo");
        await GivenIHaveAnOcelotToken("/administration");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIPostOnTheApiGateway("/administration/configuration", updatedConfiguration);
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        await ThenTheResponseShouldBe(updatedConfiguration);
        await WhenIGetUrlOnTheApiGateway("/foo");
        ThenTheResponseBodyShouldBe("/bar");
        await WhenIPostOnTheApiGateway("/administration/configuration", initialConfiguration);
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
        await ThenTheResponseShouldBe(initialConfiguration);
        await WhenIGetUrlOnTheApiGateway("/foo");
        ThenTheResponseBodyShouldBe("/foo");
    }

    [Fact]
    public async Task Should_clear_region()
    {
        const string RegionToClear = nameof(Should_clear_region);
        int ocPort = PortFinder.GetRandomPort();
        var ocUrl = DownstreamUrl(ocPort);
        var route1 = GivenRoute(PortFinder.GetRandomPort(),
            cacheOptions: new() { TtlSeconds = 10, Region = RegionToClear });
        var route2 = GivenRoute(PortFinder.GetRandomPort(),
            upstream: "/test",
            cacheOptions: new() { TtlSeconds = 10, Region = "other" });
        var configuration = GivenConfiguration(ocUrl, route1, route2);
        GivenThereIsAConfiguration(configuration);

        using var ocelot = await GivenOcelotIsRunningWithAdministration(ocUrl);
        await GivenIHaveAnOcelotToken("/administration");
        GivenIHaveAddedATokenToMyRequest();
        await WhenIDeleteUrlOnTheApiGateway($"/administration/outputcache/{RegionToClear}");
        ThenTheStatusCodeShouldBe(HttpStatusCode.NoContent);
    }

    /// <summary>
    /// Oc-Feat: <see href="https://github.com/ThreeMammals/Ocelot/issues/228">#228</see>
    /// <para>Oc-PR: <see href="https://github.com/ThreeMammals/Ocelot/pull/232">#232</see></para>
    /// </summary>
    [Fact]
    [Trait("OcFeat", "228")]
    [Trait("OcPull", "232")]
    public async Task Should_return_response_200_with_call_re_routes_controller_when_using_own_identity_server_to_secure_admin_area()
    {
        var port = PortFinder.GetRandomPort();
        var identityServerUrl = DownstreamUrl(port);
        void options(JwtBearerOptions o)
        {
            o.Authority = identityServerUrl;
            o.RequireHttpsMetadata = false;
            o.TokenValidationParameters = new()
            {
                ValidateAudience = false,
            };
        }
        int ocPort = PortFinder.GetRandomPort();
        var ocUrl = DownstreamUrl(ocPort);
        var configuration = GivenConfiguration(ocUrl);
        GivenThereIsAConfiguration(configuration);
        await GivenThereIsAnIdentityServerOn(identityServerUrl, "api");

        using var ocelot = await GivenOcelotIsRunningWithIdentityServerSettings(ocUrl, options);
        await GivenIHaveAToken(identityServerUrl);
        GivenIHaveAddedATokenToMyRequest();
        await WhenIGetUrlOnTheApiGateway("/administration/configuration");
        ThenTheStatusCodeShouldBe(HttpStatusCode.OK);
    }

    private FileConfiguration GivenConfiguration(string ocelotUrl, params FileRoute[] routes)
    {
        var c = GivenConfiguration(routes);
        c.GlobalConfiguration.BaseUrl = ocelotUrl;
        return c;
    }

    private static FileRoute GivenRoute(int port,
        string? upstream = null, string? downstream = null, FileCacheOptions? cacheOptions = null) => new()
    {
        UpstreamHttpMethod = [HttpMethods.Get],
        UpstreamPathTemplate = upstream ?? "/",
        DownstreamScheme = Uri.UriSchemeHttp,
        DownstreamPathTemplate = downstream ?? "/",
        DownstreamHostAndPorts = [ Localhost(port) ],
        FileCacheOptions = cacheOptions ?? new(),
    };

    private async Task<(IHost, HttpClient)> GivenAnotherOcelotIsRunning(string baseUrl, string ocelot2ConfigFileName)
    {
        void WithAdministration2ndConfiguration(WebHostBuilderContext hosting, IConfigurationBuilder config) => config
            .SetBasePath(hosting.HostingEnvironment.ContentRootPath)
            .AddOcelot(ocelot2ConfigFileName, false, false);
        var host = await GivenOcelotHostIsRunning
        (
            WithAdministration2ndConfiguration, // use 2nd Ocelot config
            WithAddAdministration,
            WithUseOcelot,
            (host) => host.UseUrls(baseUrl)
        );
        var client = new HttpClient()
        {
            BaseAddress = new(baseUrl)
        };
        return (host, client);
    }

    private static void GivenIdentityServerSigningEnvironmentalVariablesAreSet()
    {
        Environment.SetEnvironmentVariable(IdentityServerConfigurationCreator.OCELOT_CERTIFICATE, "mycert.pfx");
        Environment.SetEnvironmentVariable(IdentityServerConfigurationCreator.OCELOT_CERTIFICATE_PASSWORD, "password");
    }

    private async Task WhenIGetUrlOnTheSecondOcelot(HttpClient client, string url)
    {
        token.ShouldNotBeNull();
        client.DefaultRequestHeaders.Authorization = new("Bearer", token.AccessToken);
        response = await client.GetAsync(url);
    }

    private Task WhenIPostOnTheApiGateway(string url, FileConfiguration updatedConfiguration)
    {
        var json = JsonConvert.SerializeObject(updatedConfiguration);
        return WhenIPostUrlOnTheApiGateway(url, json, "application/json");
    }

    private async Task ThenTheResponseShouldBe(FileConfiguration expecteds)
    {
        var body = await response.ShouldNotBeNull().Content.ReadAsStringAsync();
        var actual = JsonConvert.DeserializeObject<FileConfiguration>(body) ?? new();
        actual.GlobalConfiguration.RequestIdKey.ShouldBe(expecteds.GlobalConfiguration.RequestIdKey);
        actual.GlobalConfiguration.ServiceDiscoveryProvider.Scheme.ShouldBe(expecteds.GlobalConfiguration.ServiceDiscoveryProvider.Scheme);
        actual.GlobalConfiguration.ServiceDiscoveryProvider.Host.ShouldBe(expecteds.GlobalConfiguration.ServiceDiscoveryProvider.Host);
        actual.GlobalConfiguration.ServiceDiscoveryProvider.Port.ShouldBe(expecteds.GlobalConfiguration.ServiceDiscoveryProvider.Port);

        for (var i = 0; i < actual.Routes.Count; i++)
        {
            for (var j = 0; j < actual.Routes[i].DownstreamHostAndPorts.Count; j++)
            {
                var result = actual.Routes[i].DownstreamHostAndPorts[j];
                var expected = expecteds.Routes[i].DownstreamHostAndPorts[j];
                result.Host.ShouldBe(expected.Host);
                result.Port.ShouldBe(expected.Port);
            }

            actual.Routes[i].DownstreamPathTemplate.ShouldBe(expecteds.Routes[i].DownstreamPathTemplate);
            actual.Routes[i].DownstreamScheme.ShouldBe(expecteds.Routes[i].DownstreamScheme);
            actual.Routes[i].UpstreamPathTemplate.ShouldBe(expecteds.Routes[i].UpstreamPathTemplate);
            actual.Routes[i].UpstreamHttpMethod.ShouldBe(expecteds.Routes[i].UpstreamHttpMethod);
        }
    }

    private async Task<BearerToken> GivenIHaveAnOcelotToken(string adminPath)
    {
        var formData = new List<KeyValuePair<string, string>>
        {
            new("client_id", "admin"),
            new("client_secret", "secret"),
            new("scope", "admin"),
            new("grant_type", "client_credentials"),
        };
        var t = await GivenIHaveATokenWithForm(adminPath, formData, ocelotClient);
        await VerifyIdentityServerStarted(adminPath, ocelotClient);
        return t;
    }

    private async Task<IHost> GivenOcelotIsRunningWithIdentityServerSettings(string ocelotUrl, Action<JwtBearerOptions> configOptions)
    {
        void WithAddAdministrationOptions(IServiceCollection services) => services
            .AddMvc(option => option.EnableEndpointRouting = false)
            .Services.AddOcelot()
            .AddAdministration("/administration", configOptions);
        var host = await GivenOcelotHostIsRunning
        (
            WithAdministrationConfiguration,
            WithAddAdministrationOptions,
            WithUseOcelot,
            (host) => host.UseUrls(ocelotUrl)
        );
        ocelotClient = new()
        {
            BaseAddress = new(ocelotUrl),
        };
        return host;
    }

    private void WithAdministrationConfiguration(WebHostBuilderContext hosting, IConfigurationBuilder config) => config
        .SetBasePath(hosting.HostingEnvironment.ContentRootPath)
        .AddOcelot(ocelotConfigFileName, false, false)
        .AddEnvironmentVariables();
    private void WithAddAdministration(IServiceCollection services) => services
        .AddMvc(s => s.EnableEndpointRouting = false)
        .Services.AddOcelot()
        .AddAdministration("/administration", "secret");

    private async Task<IHost> GivenOcelotIsRunningWithAdministration(string ocelotUrl)
    {
        var host = await GivenOcelotHostIsRunning
        (
            WithAdministrationConfiguration,
            WithAddAdministration,
            WithUseOcelot,
            (host) => host.UseUrls(ocelotUrl)
        );
        ocelotClient = new()
        {
            BaseAddress = new(ocelotUrl),
        };
        return host;
    }

    private async Task<IHost> GivenOcelotUsingBuilderIsRunning(string ocelotUrl, Func<IMvcCoreBuilder, Assembly, IMvcCoreBuilder> customBuilder)
    {
        var host = await GivenOcelotHostIsRunning
        (
            WithAdministrationConfiguration,
            (services) => services
                .AddMvc(s => s.EnableEndpointRouting = false)
                .Services.AddOcelotUsingBuilder(services.BuildServiceProvider().GetService<IConfiguration>(), customBuilder)
                .AddAdministration("/administration", "secret"),
            WithUseOcelot,
            (host) => host.UseUrls(ocelotUrl)
        );
        ocelotClient = new()
        {
            BaseAddress = new(ocelotUrl),
        };
        return host;
    }

    private Task<IHost> GivenOcelotIsRunningWithNoWebHostBuilder(string ocelotUrl)
        => GivenOcelotIsRunningWithAdministration(ocelotUrl);

    private async Task ThenTheResultHaveMultiLineIndentedJson()
    {
        const string indent = "  ";
        const int total = 52, skip = 1;
        var contentAsString = await response.ShouldNotBeNull().Content.ReadAsStringAsync();
        string[] lines = contentAsString.Split(Environment.NewLine);
        lines.Length.ShouldBeGreaterThanOrEqualTo(total);
        lines.First().ShouldNotStartWith(indent);

        lines.Skip(skip).Take(total - skip - 1).ToList()
            .ForEach(line => line.ShouldStartWith(indent));

        lines.Last().ShouldNotStartWith(indent);
    }

    public override void Dispose()
    {
        Environment.SetEnvironmentVariable(IdentityServerConfigurationCreator.OCELOT_CERTIFICATE, string.Empty);
        Environment.SetEnvironmentVariable(IdentityServerConfigurationCreator.OCELOT_CERTIFICATE_PASSWORD, string.Empty);
        base.Dispose();
    }

    private void GivenThereIsAServiceRunningOn(int port, string path) =>
        handler.GivenThereIsAServiceRunningOn(port, path, async context =>
        {
            context.Response.StatusCode = (int)HttpStatusCode.OK;
            await context.Response.WriteAsync(path);
        });
}
