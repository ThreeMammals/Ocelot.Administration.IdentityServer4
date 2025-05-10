namespace Ocelot.Administration.IdentityServer4;

public class IdentityServerConfiguration(
    string apiName,
    bool requireHttps,
    string apiSecret,
    List<string> allowedScopes,
    string credentialsSigningCertificateLocation,
    string credentialsSigningCertificatePassword)
    : IIdentityServerConfiguration
{
    public string ApiName { get; } = apiName;
    public bool RequireHttps { get; } = requireHttps;
    public List<string> AllowedScopes { get; } = allowedScopes;
    public string ApiSecret { get; } = apiSecret;
    public string CredentialsSigningCertificateLocation { get; } = credentialsSigningCertificateLocation;
    public string CredentialsSigningCertificatePassword { get; } = credentialsSigningCertificatePassword;
}
