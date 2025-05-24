using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;

namespace Ocelot.Administration.IdentityServer4;

public static class OcelotBuilderExtensions
{
    public static IOcelotAdministrationBuilder AddAdministration(this IOcelotBuilder builder, string path, string secret)
    {
        var administrationPath = new AdministrationPath(path);
        builder.Services.AddSingleton(IdentityServerMiddlewareConfigurationProvider.Get);

        //add identity server for admin area
        var identityServerConfiguration = IdentityServerConfigurationCreator.GetIdentityServerConfiguration(secret);

        if (identityServerConfiguration != null)
        {
            AddIdentityServer(identityServerConfiguration, administrationPath, builder, builder.Configuration);
        }

        builder.Services.AddSingleton<IAdministrationPath>(administrationPath);
        return new OcelotAdministrationBuilder(builder.Services, builder.Configuration);
    }

    public static IOcelotAdministrationBuilder AddAdministration(this IOcelotBuilder builder, string path, Action<JwtBearerOptions> configureOptions)
    {
        var administrationPath = new AdministrationPath(path);
        builder.Services.AddSingleton(IdentityServerMiddlewareConfigurationProvider.Get);

        if (configureOptions != null)
        {
            AddIdentityServer(builder, configureOptions);
        }

        builder.Services.AddSingleton<IAdministrationPath>(administrationPath);
        return new OcelotAdministrationBuilder(builder.Services, builder.Configuration);
    }

    private static void AddIdentityServer(IOcelotBuilder builder, Action<JwtBearerOptions> configOptions)
    {
        builder.Services
            .AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
            .AddJwtBearer(IdentityServerAuthenticationDefaults.AuthenticationScheme, configOptions);
    }

    private static void AddIdentityServer(IdentityServerConfiguration identityServerConfiguration, AdministrationPath adminPath, IOcelotBuilder builder, IConfiguration configuration)
    {
        builder.Services.TryAddSingleton<IIdentityServerConfiguration>(identityServerConfiguration);
        var identityServerBuilder = builder.Services
            .AddIdentityServer(o =>
            {
                o.IssuerUri = "Ocelot";
                o.EmitStaticAudienceClaim = true;
            })
            .AddInMemoryApiScopes(ApiScopes(identityServerConfiguration))
            .AddInMemoryApiResources(Resources(identityServerConfiguration))
            .AddInMemoryClients(Client(identityServerConfiguration));

        var urlFinder = new BaseUrlFinder(configuration);
        var baseSchemeUrlAndPort = urlFinder.Find();
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        void ConfigureOptions(JwtBearerOptions options)
        {
            options.Authority = baseSchemeUrlAndPort + adminPath.Path;
            options.RequireHttpsMetadata = identityServerConfiguration.RequireHttps;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
            };
        }
        AddIdentityServer(builder, ConfigureOptions);

        // TODO - refactor naming..
        if (string.IsNullOrEmpty(identityServerConfiguration.CredentialsSigningCertificateLocation) ||
            string.IsNullOrEmpty(identityServerConfiguration.CredentialsSigningCertificatePassword))
        {
            identityServerBuilder.AddDeveloperSigningCredential();
        }
        else
        {
            //var file = Path.Combine(AppContext.BaseDirectory, identityServerConfiguration.CredentialsSigningCertificateLocation);
            //var cert = X509CertificateLoader.LoadCertificateFromFile(file);
#pragma warning disable IDE0079 // Remove unnecessary suppression
#pragma warning disable SYSLIB0057 // X509Certificate2 and X509Certificate constructors for binary and file content are obsolete
            var cert = new X509Certificate2(identityServerConfiguration.CredentialsSigningCertificateLocation, identityServerConfiguration.CredentialsSigningCertificatePassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            identityServerBuilder.AddSigningCredential(cert);
        }
    }

    private static IEnumerable<ApiScope> ApiScopes(IdentityServerConfiguration configuration)
        => configuration.AllowedScopes.Select(s => new ApiScope(s));

    private static List<ApiResource> Resources(IdentityServerConfiguration configuration) =>
    [
        new(configuration.ApiName, configuration.ApiName)
        {
            ApiSecrets = [
                new() { Value = configuration.ApiSecret.Sha256() },
            ],
        },
    ];

    private static List<Client> Client(IdentityServerConfiguration configuration) =>
    [
        new()
        {
            ClientId = configuration.ApiName,
            AllowedGrantTypes = GrantTypes.ClientCredentials,
            ClientSecrets = [
                new(configuration.ApiSecret.Sha256())
            ],
            AllowedScopes = configuration.AllowedScopes,
        },
    ];
}
