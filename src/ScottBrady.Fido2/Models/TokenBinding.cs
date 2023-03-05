using System.Text.Json.Serialization;

namespace ScottBrady.Fido2.Models;

/// <summary>
/// The state of the Token Binding protocol used when communicating with the relying party.
/// </summary>
public class TokenBinding
{
    /// <summary>
    /// The state of Token Binding for this request.
    /// Unknown values must be ignored.
    /// </summary>
    [JsonPropertyName("status")]
    public string Status { get; set; }
    
    /// <summary>
    /// The base64url encoded Token Binding ID for this request.
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; set; }
}