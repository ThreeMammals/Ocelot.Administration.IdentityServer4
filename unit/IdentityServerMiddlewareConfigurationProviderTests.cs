using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Ocelot.Configuration.File;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using System.Runtime.CompilerServices;

namespace Ocelot.Administration.IdentityServer4.UnitTests;

public class IdentityServerMiddlewareConfigurationProviderTests : UnitTest
{
    [Fact]
    public async Task ConfigureMiddleware_HappyPath()
    {
        // Arrange
        var config = new FileConfiguration();
        var builder = WebApplication.CreateBuilder();
        builder.Configuration
            .SetBasePath(builder.Environment.ContentRootPath)
            .AddOcelot(config, builder.Environment, MergeOcelotJson.ToMemory);
        builder.Services
            .AddOcelot(builder.Configuration)
            .AddAdministration(AdminPath(), TestID);
        using var app = builder.Build();

        // Act 1
        // Ocelot core invokes OcelotMiddlewareConfigurationDelegate within UseOcelot() method of the OcelotMiddlewareExtensions class.
        // We must call UseOcelot to cover all lines of the attached helper-delegates.
        // More: https://github.com/ThreeMammals/Ocelot/blob/24.0.0/src/Ocelot/Middleware/OcelotMiddlewareExtensions.cs#L101
        await app.UseOcelot();

        // Act 2
        // Directly call the delegate
        var task = IdentityServerMiddlewareConfigurationProvider.Get.Invoke(app);

        // Assert
        Assert.NotNull(task);
        Assert.True(task.IsCompleted);
    }

    [Fact]
    public void ConfigureMiddleware_NoAdminPath()
    {
        // Arrange
        var mocking = new Mock<IApplicationBuilder>();
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        mocking.SetupGet(x => x.ApplicationServices).Returns(provider);
        var builder = mocking.Object;

        // Act
        var task = IdentityServerMiddlewareConfigurationProvider.Get.Invoke(builder);

        // Assert
        Assert.NotNull(task);
        Assert.True(task.IsCompleted);
    }

    private string AdminPath([CallerMemberName] string? testName = null)
        => $"/{nameof(IdentityServerMiddlewareConfigurationProviderTests)}/{testName ?? TestID}";
}
