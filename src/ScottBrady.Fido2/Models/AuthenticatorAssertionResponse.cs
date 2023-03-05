using System.Text.Json.Serialization;

namespace ScottBrady.Fido2.Models;

public class AuthenticatorAssertionResponse : AuthenticatorResponse
{
    [JsonPropertyName("authenticatorData")]
    public byte[] AuthenticatorData { get; set; }
    
    [JsonPropertyName("signature")]
    public byte[] Signature { get; set; }
    
    [JsonPropertyName("userHandle")]
    public byte[] UserHandle { get; set; }
}