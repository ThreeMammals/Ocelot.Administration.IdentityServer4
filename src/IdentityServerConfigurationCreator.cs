namespace Ocelot.Administration.IdentityServer4;

public static class IdentityServerConfigurationCreator
{
    public static IdentityServerConfiguration GetIdentityServerConfiguration(string secret)
    {
        var credentialsSigningCertificateLocation = Environment.GetEnvironmentVariable("OCELOT_CERTIFICATE") ?? string.Empty;
        var credentialsSigningCertificatePassword = Environment.GetEnvironmentVariable("OCELOT_CERTIFICATE_PASSWORD") ?? string.Empty;
        return new IdentityServerConfiguration(
            "admin",
            false,
            secret,
            ["admin", "openid", "offline_access"],
            credentialsSigningCertificateLocation,
            credentialsSigningCertificatePassword
        );
    }
}
