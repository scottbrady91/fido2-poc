using ScottBrady.Fido2.Models;
using ScottBrady.Fido2.Stores;

namespace ScottBrady.Fido2;

/// <summary>
/// The result of FIDO authentication.
/// Contains details about the user and credential.
/// </summary>
public class FidoAuthenticationResult
{
    private FidoAuthenticationResult() { }

    internal static FidoAuthenticationResult Success(FidoKey key, AuthenticatorData authenticatorData) => new FidoAuthenticationResult
    {
        UserId = key.UserId,
        Username = key.Username,
        CredentialId = key.CredentialId,
        UserVerified = authenticatorData.UserVerified
    };

    internal static FidoAuthenticationResult Failure(string error) => new FidoAuthenticationResult { Error = error };

    /// <summary>
    /// If authentication was successful.
    /// </summary>
    public bool IsSuccess => string.IsNullOrWhiteSpace(Error);
    
    /// <summary>
    /// Error message from validation.
    /// </summary>
    public string Error { get; private set; }
    
    /// <summary>
    /// <para>The user handle (ID) that uniquely identifies the user.</para>
    /// <para>This value is used by both the relying party and authenticator.</para>
    /// <para>This value does not contain PII (such as username or email address) and should not be displayed to the user.</para> 
    /// </summary>
    public byte[] UserId { get; private set; }
    
    /// <summary>
    /// <para>A human-readable name for the user account (e.g. "Scott Brady"), chosen by the user.</para>
    /// <para>This value can be displayed to the user and is stored by the authenticator.</para>
    /// </summary>
    public string Username { get; private set; }
    
    /// <summary>
    /// The unique identifier of the credential.
    /// This may be a 16-byte random value or an encrypted value that is understood by the authenticator.
    /// </summary>
    public byte[] CredentialId { get; private set; }
    
    /// <summary>
    /// Whether or not the user verified their identity during authentication.
    /// This is a multi-factor check, confirming if the user authenticated themselves to the authenticator with a local
    /// credential such as a PIN or a biometric.
    /// </summary>
    public bool UserVerified { get; private set; }
}