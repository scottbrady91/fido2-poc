using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ScottBrady.Fido2.Models;

/// <summary>
/// The registration options created by the WebAuthn relying party.
/// Used when calling navigator.credentials.create(). 
/// </summary>
/// <remarks>
/// Implements WebAuthn's <a href="https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions">PublicKeyCredentialCreationOptions</a> structure.
/// </remarks>
public class PublicKeyCredentialCreationOptions
{
    // TODO: constructor to enforce required fields
    
    /// <inheritdoc cref="PublicKeyCredentialRpEntity" />
    [JsonPropertyName("rp")]
    public PublicKeyCredentialRpEntity Rp { get; set; }
    
    /// <inheritdoc cref="PublicKeyCredentialUserEntity"/>
    [JsonPropertyName("user")]
    public PublicKeyCredentialUserEntity User { get; set; }

    /// <summary>
    /// <para>The cryptographically random challenge used to match an authenticator response to a WebAuthn request.</para>
    /// <para>Must be at least 16-bytes long.</para>
    /// </summary>
    [JsonPropertyName("challenge")]
    public byte[] Challenge { get; set; }
    
    /// <inheritdoc cref="PublicKeyCredentialParameters"/>
    [JsonPropertyName("pubKeyCredParams")]
    public IEnumerable<PublicKeyCredentialParameters> PublicKeyCredentialParameters { get; set; }
    
    /// <summary>
    /// <para>The number of milliseconds the client (WebAuthn API) should wait for the user to complete the registration process.</para>
    /// <para>This is a hint and may be ignored by the client.</para>
    /// </summary>
    [JsonPropertyName("timeout")]
    public int? Timeout { get; set; }
    
    /// <summary>
    /// Credentials to ignore during registration.
    /// This can prevent multiple credentials being created for the same account on a single authenticator.
    /// </summary>
    [JsonPropertyName("excludeCredentials")]
    public IEnumerable<PublicKeyCredentialDescriptor> ExcludeCredentials { get; set; }
    
    /// <summary>
    /// Criteria that an authenticator must meet in order to complete registration.
    /// </summary>
    [JsonPropertyName("authenticatorSelection")]
    public AuthenticatorSelectionCriteria AuthenticatorSelection { get; set; }

    /// <summary>
    /// <para>The relying party's preference for attestation conveyance.
    /// Should be a value from <a href="https://www.w3.org/TR/webauthn-2/#enum-attestation-convey">AttestationConveyancePreference</a>.</para>
    /// <para>Unknown values will be ignored by the client (WebAuthn API).</para>
    /// <para>Defaults to "none".</para>
    /// </summary>
    [JsonPropertyName("attestation")]
    public string Attestation { get; set; } = FidoConstants.AttestationConveyancePreference.None;

    /// <summary>
    /// Additional parameters for the client (WebAuthn API) and authenticator.
    /// See <a href="https://www.w3.org/TR/webauthn-2/#sctn-extension-request-parameters">W3C spec</a> for more details.
    /// </summary>
    [JsonPropertyName("extensions")]
    public Dictionary<string, object> Extensions { get; set; } = null;
    
    /// <summary>
    /// Optional custom field for a human-readable name for the authenticator.
    /// Allows the user to identify what authenticators they have registered at the relying party (web server).
    /// Can be set by the user during or after registration.
    /// </summary>
    public string DeviceDisplayName { get; set; } // TODO: move to options wrapper
}