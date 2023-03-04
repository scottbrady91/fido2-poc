using System;
using System.Security.Cryptography;

namespace ScottBrady.Fido2.Cryptography;

/// <summary>
/// Strategy for RSA signature validation during authentication.
/// </summary>
public class RsaSignatureValidationStrategy : ISignatureValidationStrategy
{
    /// <inheritdoc />
    public bool IsValidSignature(ReadOnlySpan<byte> data, byte[] signature, CredentialPublicKey key)
    {
        using var rsa = RSA.Create(key.LoadRsaParameters());
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, GetPadding(key.Algorithm));
    }

    private static RSASignaturePadding GetPadding(string alg)
    {
        if (alg is CoseConstants.Algorithms.PS256 or CoseConstants.Algorithms.PS384 or CoseConstants.Algorithms.PS512)
            return RSASignaturePadding.Pss;
        if (alg is CoseConstants.Algorithms.RS1 or CoseConstants.Algorithms.RS256 or CoseConstants.Algorithms.RS384
                 or CoseConstants.Algorithms.RS512) return RSASignaturePadding.Pkcs1;
        throw new FidoException("Unknown RSA algorithm");
    }
}