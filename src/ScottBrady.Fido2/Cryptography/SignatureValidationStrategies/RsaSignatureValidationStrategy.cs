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
        return rsa.VerifyData(data, signature, GetHashingAlgorithm(key.Algorithm), GetPadding(key.Algorithm));
    }

    private static RSASignaturePadding GetPadding(string alg)
    {
        return alg switch
        {
            CoseConstants.Algorithms.PS256 or CoseConstants.Algorithms.PS384 or CoseConstants.Algorithms.PS512 => RSASignaturePadding.Pss,
            CoseConstants.Algorithms.RS1 or CoseConstants.Algorithms.RS256 or CoseConstants.Algorithms.RS384 or CoseConstants.Algorithms.RS512 => RSASignaturePadding.Pkcs1,
            _ => throw new FidoException("Unknown RSA algorithm")
        };
    }

    private static HashAlgorithmName GetHashingAlgorithm(string alg)
    {
        return alg switch
        {
            CoseConstants.Algorithms.RS256 or CoseConstants.Algorithms.PS256 => HashAlgorithmName.SHA256,
            CoseConstants.Algorithms.RS384 or CoseConstants.Algorithms.PS384 => HashAlgorithmName.SHA384,
            CoseConstants.Algorithms.RS512 or CoseConstants.Algorithms.PS512 => HashAlgorithmName.SHA512,
            CoseConstants.Algorithms.RS1 => HashAlgorithmName.SHA1,
            _ => throw new FidoException("Unknown RSA algorithm")
        };   
    }
}