using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ScottBrady.Fido2.Models;

/// <summary>
/// The authentication options created by the WebAuthn relying party.
/// Used when calling navigator.credentials.get(). 
/// </summary>
/// <remarks>
/// Implements WebAuthn's  <a href="https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options">PublicKeyCredentialRequestOptions</a> structure.
/// </remarks>
public class PublicKeyCredentialRequestOptions
{
    /// <summary>
    /// Creates a new PublicKeyCredentialRequestOptions.
    /// </summary>
    /// <param name="challenge">A cryptographically random challenge value</param>
    /// <exception cref="ArgumentNullException">Missing challenge</exception>
    [JsonConstructor]
    public PublicKeyCredentialRequestOptions(byte[] challenge)
    {
        Challenge = challenge ?? throw new ArgumentNullException(nameof(challenge));
    }
    
    /// <summary>
    /// <para>The cryptographically random challenge used to match an authenticator response to a WebAuthn request.</para>
    /// <para>Must be at least 16-bytes long.</para>
    /// </summary>
    [JsonPropertyName("challenge")]
    public byte[] Challenge { get; }
    
    /// <summary>
    /// <para>The number of milliseconds the client (WebAuthn API) should wait for the user to complete the registration process.</para>
    /// <para>This is a hint and may be ignored by the client.</para>
    /// </summary>
    [JsonPropertyName("timeout")]
    public int? Timeout { get; set; }

    /// <summary>
    /// <para>The ID that uniquely identifies the relying party (web application).
    /// This is the <a href="https://www.w3.org/TR/webauthn-2/#rp-id">RP ID</a> used by the WebAuthn API.</para>
    /// <para>Must be a valid domain string and must be a registrable domain suffix of or is equal to the caller’s origin's effective domain
    /// (e.g. for an origin of https://login.example.com:1337, the RP ID is login.example.com or example.com).</para>
    /// If not provided, defaults to the origin's effective domain.
    /// </summary>
    /// <example>login.example.com</example>
    [JsonPropertyName("rpId")]
    public string RpId { get; set; }
    
    /// <summary>
    /// An ordered collection of credentials that the identified user can use to authenticate with.
    /// The first credential is the most preferred.
    /// </summary>
    [JsonPropertyName("allowCredentials")]
    public IEnumerable<PublicKeyCredentialDescriptor> AllowCredentials { get; set; }

    /// <summary>
    /// <para>The relying party's requirement for user verification (e.g. a local PIN or biometric to use the authenticator).
    /// Only authenticators that meet this requirement will be challenged.
    /// Should be a <a href="https://www.w3.org/TR/webauthn-2/#enumdef-userverificationrequirement">User Verification Requirement</a>, but open to future extensibility.</para>
    /// <para>Unknown values will be ignored by the client.</para>
    /// <para>Defaults to "preferred"</para>
    /// </summary>
    /// <example>preferred</example>
    [JsonPropertyName("userVerification")]
    public string UserVerification { get; set; } = WebAuthnConstants.UserVerificationRequirement.Preferred;
    
    /// <summary>
    /// Additional parameters for the client (WebAuthn API) and authenticator.
    /// See <a href="https://www.w3.org/TR/webauthn-2/#sctn-extension-request-parameters">W3C spec</a> for more details.
    /// </summary>
    [JsonPropertyName("extensions")]
    public Dictionary<string, object> Extensions { get; set; }
}