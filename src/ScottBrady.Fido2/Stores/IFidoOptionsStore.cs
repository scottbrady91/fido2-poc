using System.Threading.Tasks;
using ScottBrady.Fido2.Models;

namespace ScottBrady.Fido2.Stores;

/// <summary>
/// Storage layer for FIDO options, created when initiating registration and authentication.
/// </summary>
public interface IFidoOptionsStore
{
    /// <summary>
    /// Stores the generated <see cref="PublicKeyCredentialCreationOptions"/>.
    /// </summary>
    /// <param name="options"></param>
    Task Store(PublicKeyCredentialCreationOptions options);

    /// <summary>
    /// Stores the generated <see cref="PublicKeyCredentialRequestOptions"/>.
    /// </summary>
    /// <param name="options"></param>
    Task Store(PublicKeyCredentialRequestOptions options);
    
    /// <summary>
    /// Gets the stored <see cref="PublicKeyCredentialCreationOptions"/> for the current request.
    /// Can use the challenge as a lookup key.
    /// </summary>
    /// <param name="challenge"></param>
    Task<PublicKeyCredentialCreationOptions> TakeRegistrationOptions(byte[] challenge);

    /// <summary>
    /// Gets the stored <see cref="FidoAuthenticationOptions"/> for the current request.
    /// Can use the challenge as a lookup key.
    /// </summary>
    /// <param name="challenge"></param>
    Task<PublicKeyCredentialRequestOptions> TakeAuthenticationOptions(byte[] challenge);
}