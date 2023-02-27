using System;

namespace ScottBrady.Fido2.Cryptography;

public interface ISignatureValidationStrategy
{
    bool ValidateSignature(ReadOnlySpan<byte> data, byte[] signature, CredentialPublicKey key);
}