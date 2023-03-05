using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using ScottBrady.Fido2.Cryptography;

namespace ScottBrady.Fido2;

/// <summary>
/// Library configuration options.
/// </summary>
public class FidoOptions
{
    /// <summary>
    /// <para>Overrides the ID that uniquely identifies the relying party (web application).
    /// This is the <a href="https://www.w3.org/TR/webauthn-2/#rp-id">RP ID</a> used by the WebAuthn API.</para>
    /// <para>Must be a valid domain string and must be a registrable domain suffix of or is equal to the caller’s origin's effective domain
    /// (e.g. for an origin of https://login.example.com:1337, the RP ID is login.example.com or example.com).</para>
    /// If not provided, defaults to the origin's effective domain.
    /// </summary>
    /// <example>login.example.com</example>
    public string RelyingPartyId { get; set; }
    
    /// <summary>
    /// <para>A human-readable identifier for the relying party (web application), set by the relying party.</para>
    /// <para>This value can be displayed to the user and will be stored by the authenticator.</para>
    /// <para>May be truncated by the authenticator if over 64-bytes.</para>
    /// </summary>
    /// <example>ACME Corp</example>
    public string RelyingPartyName { get; set; }

    /// <summary>
    /// A dictionary of strategies for WebAuthn signature validation.
    /// Key must be <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">an algorithm in from the COSE standard</a>.
    /// See <see cref="CoseConstants.Algorithms"/> constants class for known algorithm values.
    /// </summary>
    /// <value>Out-of-the-box support for ES256, ES384, ES512, RS256, RS384, and RS512</value>
    // TODO: how to improve strategy? Leave in options? Copy every time? Move to factory?
    public Dictionary<string, Func<ISignatureValidationStrategy>> SigningAlgorithmStrategies = 
        new Dictionary<string, Func<ISignatureValidationStrategy>>
        {
            { CoseConstants.Algorithms.ES256, () => new EcdsaSignatureValidationStrategy() },
            { CoseConstants.Algorithms.ES384, () => new EcdsaSignatureValidationStrategy() },
            { CoseConstants.Algorithms.ES512, () => new EcdsaSignatureValidationStrategy() },
            { CoseConstants.Algorithms.RS256, () => new RsaSignatureValidationStrategy() },
            { CoseConstants.Algorithms.RS384, () => new RsaSignatureValidationStrategy() },
            { CoseConstants.Algorithms.RS512, () => new RsaSignatureValidationStrategy() }
            // TODO: RS1?
            // TODO: EdDSA?
        };

    public JsonSerializerOptions JsonOptions { get; set; } = new JsonSerializerOptions
    {
        Converters = { new IntArrayJsonConverter(), new EmptyToNullStringConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
        PropertyNameCaseInsensitive = true
    }; // TODO: check handling style in Microsoft.IdentityModel
}