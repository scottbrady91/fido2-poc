using System.Text.Json.Serialization;

namespace ScottBrady.Fido2.Models;

/// <summary>
/// Criteria that an authenticator must meet in order to complete registration.
/// </summary>
/// <remarks>
/// Implements WebAuthn's <a href="https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria">AuthenticatorSelectionCriteria</a> structure.
/// </remarks>
public class AuthenticatorSelectionCriteria
{
    /// <summary>
    /// <para>Filters authenticators by attachment style (e.g. "platform" or "cross-platform").
    /// Should be a <a href="https://www.w3.org/TR/webauthn-2/#enum-attachment">Authenticator Attachment</a>, but open to future extensibility.</para>
    /// <para>Unknown values will be ignored by the client.</para>
    /// </summary>
    /// <example>cross-platform</example>
    [JsonPropertyName("authenticatorAttachment")]
    public string AuthenticatorAttachment { get; set; }
    
    /// <summary>
    /// <para>The extent to which the relying party (web server) requires a client-side discoverable credential (think usernameless authentication).
    /// If not present, the client (WebAuthn API) will treat the value as "required" if <see cref="RequireResidentKey"/> is true or "discouraged" if false or absent.
    /// Should be a <a href="https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement">Resident Key Requirement</a>, but open to future extensibility.</para>
    /// <para>Unknown values will be ignored by the client.</para> 
    /// </summary>
    /// <example>discouraged</example>
    [JsonPropertyName("residentKey")]
    public string ResidentKey { get; set; }
    
    /// <summary>
    /// Backwards compatible setting for WebAuthn Level 1.
    /// Should be true only if <see cref="ResidentKey"/> is set to "required".
    /// </summary>
    [JsonPropertyName("requireResidentKey")]
    public bool RequireResidentKey { get; set; } = false;
    
    /// <summary>
    /// <para>The relying party's requirement for user verification (e.g. a local PIN or biometric to use the authenticator).
    /// Should be a <a href="https://www.w3.org/TR/webauthn-2/#enumdef-userverificationrequirement">User Verification Requirement</a>, but open to future extensibility.</para>
    /// <para>Unknown values will be ignored by the client.</para>
    /// <para>Defaults to "preferred"</para>
    /// </summary>
    /// <example>preferred</example>
    [JsonPropertyName("userVerification")]
    public string UserVerification { get; set; } = "preferred";
}