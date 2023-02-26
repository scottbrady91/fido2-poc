using System.Collections.Generic;

namespace ScottBrady.Fido2.Models;

/// <summary>
/// Describes a public key credential.
/// Used to disallow existing credentials during registration or request specific credentials during authentication.
/// </summary>
/// <remarks>
/// Implements WebAuthn's <a href="https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor">PublicKeyCredentialDescriptor</a> structure.
/// </remarks>
public class PublicKeyCredentialDescriptor
{
    /// <summary>
    /// <para>The type of credential being described.
    /// Should be <a href="https://www.w3.org/TR/webauthn-2/#enumdef-publickeycredentialtype">"public-key"</a>, but open to future extensibility.</para>
    /// <para>Unknown values will be ignored by the client (WebAuthn API).</para>
    /// </summary>
    /// <example>public-key</example>
    public string Type { get; set; }
    
    /// <summary>
    /// The ID of the credential to ignore.
    /// </summary>
    public byte[] Id { get; set; }
    
    /// <summary>
    /// <para>Hints how the client (WebAuthn API) should communicate with the credential.
    /// Should be a value from <a href="https://www.w3.org/TR/webauthn-2/#enumdef-authenticatortransport">AuthenticatorTransport</a>.</para>
    /// <para>Unknown values will be ignored by the client (WebAuthn API).</para>
    /// </summary>
    public IEnumerable<string> Transports { get; set; }
}