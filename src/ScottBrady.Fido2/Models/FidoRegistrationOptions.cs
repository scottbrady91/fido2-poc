using System.Collections.Generic;

namespace ScottBrady.Fido2.Models;

/// <summary>
/// The registration options created by the WebAuthn relying party.
/// Used when calling navigator.credentials.create(). 
/// </summary>
/// <remarks>
/// This library's implementation of the <a href="https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions">PublicKeyCredentialCreationOptions</a> structure.
/// </remarks>
public class FidoRegistrationOptions
{
    // TODO: constructor to enforce required fields
    
    /// <inheritdoc cref="RelyingParty" />
    public RelyingParty RelyingParty { get; set; }
    
    /// <inheritdoc cref="User"/>
    public User User { get; set; }

    /// <summary>
    /// <para>The cryptographically random challenge used to match an authenticator response to a WebAuthn request.</para>
    /// <para>Must be at least 16-bytes long.</para>
    /// </summary>
    public byte[] Challenge { get; set; }
    
    public PublicKeyCredentialParameters PublicKeyCredentialParameters { get; set; }
    
    public int? Timeout { get; set; }
    
    public ServerPublicKeyCredentialDescriptor ExcludeCredentials { get; set; }
    
    public AuthenticatorSelectionCriteria AuthenticatorSelectionCriteria { get; set; }
    
    public AttestationConveyancePreference AttestationConveyancePreference { get; set; }
    
    public Dictionary<string, object> Extensions { get; set; }
    
    
    // TODO: consider full API (publicCredParams, timeout, excludeCredentials, authenticatorSelection, attestation, extensions)
}

/// <summary>
/// The relying party (web application) details used when creating a new credential.
/// </summary>
/// <remarks>
/// This library's implementation of the <a href="https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params">PublicKeyCredentialRpEntity</a> structure.
/// </remarks>
public class RelyingParty
{
    /// <summary>
    /// <para>The ID that uniquely identifies the relying party (web application).
    /// This is the <a href="https://www.w3.org/TR/webauthn-2/#rp-id">RP ID</a> used by the WebAuthn API.</para>
    /// <para>Must be a valid domain string and must be a registrable domain suffix of or is equal to the caller’s origin's effective domain
    /// (e.g. for an origin of https://login.example.com:1337, the RP ID is login.example.com or example.com).</para>
    /// If not provided, defaults to the origin's effective domain.
    /// </summary>
    /// <example>login.example.com</example>
    public string Id { get; set; }

    /// <summary>
    /// <para>A human-readable identifier for the relying party (web application), set by the relying party.</para>
    /// <para>This value can be displayed to the user and will be stored by the authenticator.</para>
    /// <para>May be truncated by the authenticator if over 64-bytes.</para>
    /// </summary>
    /// <example>ACME Corp</example>
    public string Name { get; set; }
}

/// <summary>
/// The user account details used when creating a new credential.
/// </summary>
/// <remarks>
/// This library's implementation of the <a href="https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialuserentity">PublicKeyCredentialUserEntity</a> structure.
/// </remarks>
public class User
{
    /// <summary>
    /// <para>The user handle (ID) that will uniquely  identify the user.</para>
    /// <para>This value will be used by both the relying party and authenticator.</para>
    /// <para>This value must not contain PII (such as username or email address) and should not be displayed to the user.</para>
    /// <para>Maximum size of 64-bytes.</para>
    /// </summary>
    /// <remarks>
    /// It is recommended that you use 64 random bytes for this value.
    /// See <a href="https://www.w3.org/TR/webauthn-2/#sctn-user-handle-privacy">W3C guidance for security considerations</a>.
    /// </remarks>
    public byte[] Id { get; set; }

    /// <summary>
    /// <para>A human-readable name for the user account (e.g. "Scott Brady"), chosen by the user.</para>
    /// <para>This value can be displayed to the user and will be stored by the authenticator.</para>
    /// <para>May be truncated by the authenticator if over 64-bytes.</para>
    /// </summary>
    public string DisplayName { get; set; }

    /// <summary>
    /// <para>A human-readable identifier for the user account, chosen by the user.</para>
    /// <para>Used to differentiate between user accounts with similar display names.</para>
    /// <para>This value can be displayed to the user and will be stored by the authenticator.</para>
    /// <para>May be truncated by the authenticator if over 64-bytes.</para>
    /// </summary>
    public string Name { get; set; }
}


public class PublicKeyCredentialParameters
{
    public string Type { get; set; }
    public int Algorithm { get; set; }
}

public class ServerPublicKeyCredentialDescriptor
{
    public PublicKeyCredentialType Type { get; set; }
    public string Id { get; set; }
    public IEnumerable<AuthenticatorTransport> Transports { get; set; }
}

// https://w3c.github.io/webauthn/#enum-transport
public enum AuthenticatorTransport // TODO: future proof enums with strings?
{
    Usb,
    Nfc,
    Ble,
    Hybrid,
    Internal
}

// https://w3c.github.io/webauthn/#enum-credentialType
public enum PublicKeyCredentialType
{
    // "public-key"
    PublicKey
}