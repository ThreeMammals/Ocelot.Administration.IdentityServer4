﻿using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Ocelot.Configuration.Repository;

namespace Ocelot.Administration.IdentityServer4;

public static class IdentityServerMiddlewareConfigurationProvider
{
    public static OcelotMiddlewareConfigurationDelegate Get { get; } = Getter;

    private static Task Getter(IApplicationBuilder builder)
    {
        var repo = builder.ApplicationServices.GetService<IInternalConfigurationRepository>();
        var config = repo?.Get();

        if (!string.IsNullOrEmpty(config?.Data.AdministrationPath))
        {
            builder.Map(config.Data.AdministrationPath, app =>
            {
                //todo - hack so we know that we are using internal identity server
                var identityServerConfiguration = builder.ApplicationServices.GetService<IIdentityServerConfiguration>();

                if (identityServerConfiguration != null)
                {
                    app.UseIdentityServer();
                }

                app.UseAuthentication();
                app.UseRouting();
                app.UseAuthorization();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapDefaultControllerRoute();
                    endpoints.MapControllers();
                });
            });
        }

        return Task.CompletedTask;
    }
}
