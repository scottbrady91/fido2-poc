using System;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace ScottBrady.Fido2.Cryptography;

public class EcdsaSignatureValidationStrategy : ISignatureValidationStrategy
{
    public bool ValidateSignature(ReadOnlySpan<byte> data, byte[] signature, CredentialPublicKey key)
    {
        using var ecDsa = ECDsa.Create(key.LoadEcParameters());
        return ecDsa.VerifyData(data, DeserializeSignature(signature), HashAlgorithmName.SHA256);
    }
    
    // https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-sig-format-compat
    public byte[] DeserializeSignature(byte[] signature)
    {
        var reader = new AsnReader(signature, AsnEncodingRules.DER);
        
        var sequence = reader.ReadSequence(Asn1Tag.Sequence);
        var r = sequence.ReadIntegerBytes(Asn1Tag.Integer);
        var s = sequence.ReadIntegerBytes(Asn1Tag.Integer);

        // remove negative flags
        if (r.Span[0] == 0x0) r = r[1..];
        if (s.Span[0] == 0x0) s = s[1..];

        // combine r and s
        var parsedSignature = new byte[r.Length + s.Length];
        r.Span.CopyTo(parsedSignature);
        s.Span.CopyTo(parsedSignature.AsSpan()[r.Length..]);

        return parsedSignature;
    }
}