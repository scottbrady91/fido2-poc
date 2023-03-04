using System;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace ScottBrady.Fido2.Cryptography;

/// <summary>
/// Strategy for ECDSA signature validation during authentication.
/// </summary>
public class EcdsaSignatureValidationStrategy : ISignatureValidationStrategy
{
    /// <inheritdoc />
    public bool IsValidSignature(ReadOnlySpan<byte> data, byte[] signature, CredentialPublicKey key)
    {
        using var ecDsa = ECDsa.Create(key.LoadEcParameters());
        return ecDsa.VerifyData(data, DecodeSignature(signature), HashAlgorithmName.SHA256);
    }
    
    /// <summary>
    /// Decode the ECDSA signature from a <a href="https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types">ASN.1 DER Ecdsa-Sig-Value</a>.
    /// </summary>
    /// <param name="signature">The signature received from the WebAuthn response</param>
    /// <returns>The decoded signature</returns>
    public static byte[] DecodeSignature(byte[] signature)
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