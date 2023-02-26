namespace ScottBrady.Fido2.Models;

/// <summary>
/// The user account details used when creating a new credential.
/// </summary>
/// <remarks>
/// This library's implementation of the <a href="https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialuserentity">PublicKeyCredentialUserEntity</a> structure.
/// </remarks>
public class PublicKeyCredentialUserEntity
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