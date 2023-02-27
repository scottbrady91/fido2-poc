using System.Text.Json.Serialization;

namespace ScottBrady.Fido2.Models;

/// <summary>
/// The parameters to use when creating a new credential.
/// </summary>
/// <remarks>
/// This library's implementation of <a href="https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialparameters">PublicKeyCredentialParameters</a>
/// </remarks>
public class PublicKeyCredentialParameters
{
    /// <summary>
    /// <para>The type of credential to be created.
    /// Should be <a href="https://www.w3.org/TR/webauthn-2/#enumdef-publickeycredentialtype">"public-key"</a>, but open to future extensibility.</para>
    /// <para>Unknown values will be ignored by the client (WebAuthn API).</para>
    /// </summary>
    /// <example>public-key</example>
    [JsonPropertyName("type")]
    public string Type { get; set; }
    
    /// <summary>
    /// The signing algorithm that should be used for the new credential.
    /// Must be a <a href="https://www.w3.org/TR/webauthn-2/#typedefdef-cosealgorithmidentifier">COSEAlgorithmIdentifier</a>
    /// </summary>
    /// <example>-7</example>
    [JsonPropertyName("alg")]
    public int Algorithm { get; set; }
}