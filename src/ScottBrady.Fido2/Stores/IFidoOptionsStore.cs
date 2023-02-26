using System.Threading.Tasks;
using ScottBrady.Fido2.Models;

namespace ScottBrady.Fido2.Stores;

/// <summary>
/// Storage layer for FIDO options, created when initiating registration and authentication.
/// </summary>
public interface IFidoOptionsStore
{
    /// <summary>
    /// Stores the generated <see cref="FidoRegistrationOptions"/>.
    /// </summary>
    /// <param name="options"></param>
    Task Store(FidoRegistrationOptions options);

    /// <summary>
    /// Stores the generated <see cref="FidoAuthenticationOptions"/>.
    /// </summary>
    /// <param name="options"></param>
    Task Store(FidoAuthenticationOptions options);
    
    /// <summary>
    /// Gets the stored <see cref="FidoRegistrationOptions"/> for the current request.
    /// Can use the challenge as a lookup key.
    /// </summary>
    /// <param name="challenge"></param>
    Task<FidoRegistrationOptions> TakeRegistrationOptions(byte[] challenge);

    /// <summary>
    /// Gets the stored <see cref="FidoAuthenticationOptions"/> for the current request.
    /// Can use the challenge as a lookup key.
    /// </summary>
    /// <param name="challenge"></param>
    Task<FidoAuthenticationOptions> TakeAuthenticationOptions(byte[] challenge);
}