using System;
using ScottBrady.IdentityModel.Tokens;

namespace ScottBrady.Fido2.Cryptography;

/// <summary>
/// Strategy for EdDSA signature validation during authentication.
/// </summary>
public class EdDsaSignatureValidationStrategy : ISignatureValidationStrategy
{
    /// <inheritdoc />
    public bool IsValidSignature(ReadOnlySpan<byte> data, byte[] signature, CredentialPublicKey key)
    {
        var edDsa = EdDsa.Create(key.LoadEdDsaParameters());
        return edDsa.Verify(data.ToArray(), signature);
    }
}