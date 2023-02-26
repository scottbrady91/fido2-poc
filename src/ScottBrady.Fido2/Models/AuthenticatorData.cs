using PeterO.Cbor;

namespace ScottBrady.Fido2.Models;

/// <summary>
/// Contains the bindings between the authenticator and relying party (web server), such as the public key,
/// signature counter, the RP ID used, and if the user proved their presence or verified themselves.
/// </summary>
/// <remarks>
/// This library's implementation of the <a href="https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data">authenticator data</a> structure.
/// </remarks>
public class AuthenticatorData
{
    /// <summary>
    /// A SHA-256 hash of the RP ID used during registration or authentication.
    /// Must match the RP ID of this relying party (web server).
    /// </summary>
    public byte[] RpIdHash { get; set; }
    
    /// <summary>
    /// Whether or not the user proved their presence during registration or authentication.
    /// This is an intent check, to prevent authenticator use without the user's knowledge.
    /// For example, if the user pressed a button on a security key or clicked a button in Windows Hello.
    /// </summary>
    public bool UserPresent { get; set; }
    
    /// <summary>
    /// Whether or not the user verified their identity during registration or authentication.
    /// This is a multi-factor check, confirming if the user authenticated themselves to the authenticator with a local
    /// credential such as a PIN or a biometric.
    /// </summary>
    public bool UserVerified { get; set; }
    
    /// <summary>
    /// Whether or not the authenticator included any attestation credentials.
    /// 
    /// </summary>
    public bool AttestedCredentialDataIncluded { get; set; }
    
    /// <summary>
    /// Whether or not the authenticator data has extensions.
    /// </summary>
    public bool ExtensionDataIncluded { get; set; }
    
    /// <summary>
    /// The signature counter.
    /// Used to detect if an authenticator has been cloned.
    /// </summary>
    public int SignCount { get; set; }
    
    
    /// <summary>
    /// The Authenticator Attestation GUID (AAGUID) of the authenticator.
    /// Will be all 0s if no attestation available.
    /// </summary>
    public byte[] Aaguid { get; set; }
    
    /// <summary>
    /// The unique identifier of the credential.
    /// This may be a 16-byte random value or an encrypted value that is understood by the authenticator.
    /// </summary>
    public byte[] CredentialId { get; set; }
    
    /// <summary>
    /// The public key bound to the authenticator, scoped to this relying party (web server).
    /// </summary>
    public string CredentialPublicKeyAsJson { get; set; }
    
    
    /// <summary>
    /// Further authenticator data, defined as extensions.
    /// Not used by this library.
    /// </summary>
    public CBORObject Extensions { get; set; }
}