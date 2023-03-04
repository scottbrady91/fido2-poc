using System;

namespace ScottBrady.Fido2.Cryptography;

/// <summary>
/// Strategy for WebAuthn signature validation during authentication.
/// TODO: document how to register new strategies 
/// </summary>
public interface ISignatureValidationStrategy
{
    /// <summary>
    /// Validates the signature using the supplied key and data.
    /// </summary>
    /// <param name="data">The data used to generate the signature</param>
    /// <param name="signature">The signature to validate</param>
    /// <param name="key">The public key with which to validate the signature</param>
    /// <returns>Is valid signature</returns>
    bool IsValidSignature(ReadOnlySpan<byte> data, byte[] signature, CredentialPublicKey key);
}