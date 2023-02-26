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
    
    public byte[] UserId { get; private set; }
    public string Username { get; private set; }
    public byte[] CredentialId { get; private set; }
    public bool UserVerified { get; private set; }
}