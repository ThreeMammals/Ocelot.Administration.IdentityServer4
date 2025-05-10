using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Ocelot.DependencyInjection;
using System.Reflection;

namespace Ocelot.Administration.IdentityServer4.UnitTests;

public class OcelotAdministrationBuilderTests : UnitTest
{
    private readonly IServiceCollection _services;
    private readonly IConfiguration _configRoot;

    public OcelotAdministrationBuilderTests()
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
            .Returns(typeof(OcelotAdministrationBuilderTests).GetTypeInfo().Assembly.GetName().Name!);
        return environment.Object;
    }

    [Fact]
    public void ShouldSetUpAdministrationWithIdentityServerOptions()
    {
        // Arrange
        static void options(JwtBearerOptions o)
        {
        }

        // Act
        var ocelotBuilder = _services.AddOcelot(_configRoot);
        ocelotBuilder.AddAdministration("/administration", options);

        // Assert
        ThenTheCorrectAdminPathIsRegitered();
    }

    [Fact]
    public void ShouldSetUpAdministration()
    {
        // Arrange, Act
        var ocelotBuilder = _services.AddOcelot(_configRoot);
        ocelotBuilder.AddAdministration("/administration", "secret");

        // Assert
        ThenTheCorrectAdminPathIsRegitered();
    }

    private void ThenTheCorrectAdminPathIsRegitered()
    {
        var provider = _services.BuildServiceProvider(true);
        var path = provider.GetService<IAdministrationPath>();
        Assert.Equal("/administration", path?.Path);
    }
}
