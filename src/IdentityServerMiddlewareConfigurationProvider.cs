using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Ocelot.Administration.IdentityServer4;

public static class IdentityServerMiddlewareConfigurationProvider
{
    public static OcelotMiddlewareConfigurationDelegate Get { get; } = ConfigureMiddleware;

    private static Task ConfigureMiddleware(IApplicationBuilder builder)
    {
        var adminPath = builder.ApplicationServices.GetService<IAdministrationPath>();
        if (!string.IsNullOrEmpty(adminPath?.Path))
        {
            builder.Map(adminPath.Path, UseIdentityServerMiddleware);
        }
        return Task.CompletedTask;
    }

    private static void UseIdentityServerMiddleware(IApplicationBuilder app)
    {
        // TODO hack so we know that we are using internal identity server
        var identityServerConfiguration = app.ApplicationServices.GetService<IIdentityServerConfiguration>();
        if (identityServerConfiguration != null)
        {
            app.UseIdentityServer();
        }

        app.UseAuthentication();
        app.UseRouting();
        app.UseAuthorization();
        app.UseEndpoints(ConfigureEndpoints);
    }

    private static void ConfigureEndpoints(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapDefaultControllerRoute();
        endpoints.MapControllers();
    }
}
