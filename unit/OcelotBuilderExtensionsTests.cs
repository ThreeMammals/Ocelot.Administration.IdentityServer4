using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Ocelot.DependencyInjection;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace Ocelot.Administration.IdentityServer4.UnitTests;

public class OcelotBuilderExtensionsTests : UnitTest
{
    private readonly IServiceCollection _services;
    private readonly IConfiguration _configRoot;

    public OcelotBuilderExtensionsTests()
    {
        _configRoot = new ConfigurationRoot([]);
        _services = new ServiceCollection();
        _services.AddSingleton(GetHostingEnvironment());
        _services.AddSingleton(_configRoot);
    }

    private static IWebHostEnvironment GetHostingEnvironment()
    {
        var environment = new Mock<IWebHostEnvironment>();
        environment.Setup(e => e.ApplicationName)
            .Returns(typeof(OcelotBuilderExtensionsTests).GetTypeInfo().Assembly.GetName().Name!);
        return environment.Object;
    }

    [Fact]
    public void AddAdministration_WithSecret_AdminPathIsRegistered()
    {
        // Arrange
        var adminPath = AdminPath();

        // Act
        var ocelotBuilder = _services.AddOcelot(_configRoot);
        ocelotBuilder.AddAdministration(adminPath, TestID);
        var provider = _services.BuildServiceProvider(true);

        // Assert
        AssertCorrectAdminPathIsRegistered(provider, adminPath);
        AssertKeysStoreIsRegistered(provider);
    }

    [Fact]
    public void AddAdministration_WithSecretAndWithSigningCertificateEnvVars_AdminPathIsRegistered()
    {
        // Arrange
        var adminPath = AdminPath();
        Environment.SetEnvironmentVariable(IdentityServerConfigurationCreator.OCELOT_CERTIFICATE, "mycert.pfx");
        Environment.SetEnvironmentVariable(IdentityServerConfigurationCreator.OCELOT_CERTIFICATE_PASSWORD, "password");

        // Act
        var ocelotBuilder = _services.AddOcelot(_configRoot);
        ocelotBuilder.AddAdministration(adminPath, "password");
        var provider = _services.BuildServiceProvider(true);

        // Assert
        AssertCorrectAdminPathIsRegistered(provider, adminPath);
        AssertKeysStoreIsRegistered(provider);
    }

    [Fact]
    public void AddAdministration_WithIdentityServerOptions_AdminPathIsRegistered()
    {
        // Arrange
        var adminPath = AdminPath();
        static void options(JwtBearerOptions o)
        {
        }

        // Act
        var ocelotBuilder = _services.AddOcelot(_configRoot);
        ocelotBuilder.AddAdministration(adminPath, options);
        var provider = _services.BuildServiceProvider(true);

        // Assert
        AssertCorrectAdminPathIsRegistered(provider, adminPath);
    }

    private string AdminPath([CallerMemberName] string? testName = null)
        => $"/{nameof(OcelotBuilderExtensionsTests)}/{testName ?? TestID}";

    private static void AssertCorrectAdminPathIsRegistered(ServiceProvider provider, string expected)
    {
        var path = provider.GetService<IAdministrationPath>();
        Assert.Equal(expected, path?.Path);
    }

    private static void AssertKeysStoreIsRegistered(ServiceProvider provider)
    {
        // builder.Services.AddSingleton<IValidationKeysStore>(new InMemoryValidationKeysStore(new[] { keyInfo }));
        var store = provider.GetService<IValidationKeysStore>();
        Assert.NotNull(store);
        IEnumerable<SecurityKeyInfo> sKeys = store.GetValidationKeysAsync().Result;
        SecurityKeyInfo sk = sKeys.First();
        Assert.NotNull(sk);
    }
}
