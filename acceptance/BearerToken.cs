using Newtonsoft.Json;

namespace Ocelot.Administration.IdentityServer4.AcceptanceTests;

public class BearerToken
{
    [JsonProperty("access_token")]
    public string AccessToken { get; set; }

    [JsonProperty("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonProperty("token_type")]
    public string TokenType { get; set; }
}
