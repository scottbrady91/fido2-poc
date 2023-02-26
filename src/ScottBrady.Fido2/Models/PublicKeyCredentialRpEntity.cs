using System.Text.Json.Serialization;

namespace ScottBrady.Fido2.Models;

/// <summary>
/// The relying party (web application) details used when creating a new credential.
/// </summary>
/// <remarks>
/// This library's implementation of the <a href="https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params">PublicKeyCredentialRpEntity</a> structure.
/// </remarks>
public class PublicKeyCredentialRpEntity
{
    /// <summary>
    /// <para>The ID that uniquely identifies the relying party (web application).
    /// This is the <a href="https://www.w3.org/TR/webauthn-2/#rp-id">RP ID</a> used by the WebAuthn API.</para>
    /// <para>Must be a valid domain string and must be a registrable domain suffix of or is equal to the caller’s origin's effective domain
    /// (e.g. for an origin of https://login.example.com:1337, the RP ID is login.example.com or example.com).</para>
    /// If not provided, defaults to the origin's effective domain.
    /// </summary>
    /// <example>login.example.com</example>
    [JsonPropertyName("id")]
    public string Id { get; set; }

    /// <summary>
    /// <para>A human-readable identifier for the relying party (web application), set by the relying party.</para>
    /// <para>This value can be displayed to the user and will be stored by the authenticator.</para>
    /// <para>May be truncated by the authenticator if over 64-bytes.</para>
    /// </summary>
    /// <example>ACME Corp</example>
    [JsonPropertyName("name")]
    public string Name { get; set; }
}