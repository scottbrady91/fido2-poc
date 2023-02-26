﻿using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.Fido2.Cryptography;

public class EcdsaSignatureValidationStrategy : ISignatureValidationStrategy
{
    public bool ValidateSignature(ReadOnlySpan<byte> data, byte[] signature, string keyAsJson)
    {
        var jsonNode = JsonNode.Parse(keyAsJson);
        if (jsonNode == null) throw new Exception("unable to load json");
        
        var kty = jsonNode["1"]?.GetValue<int>(); // TODO: pull COSE keys into constants
        var alg = jsonNode["3"]?.GetValue<int>();
        var crv = jsonNode["-1"]?.GetValue<int>();
        
        var x = jsonNode["-2"]?.GetValue<string>();
        var y = jsonNode["-3"]?.GetValue<string>();
        
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256, // TODO: map curve & hashing algorithm from COSE alg value
            Q = new ECPoint
            {
                X = Base64UrlEncoder.DecodeBytes(x),
                Y = Base64UrlEncoder.DecodeBytes(y)
            }
        };

        using var ecDsa = ECDsa.Create(parameters);
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
    
    // TODO: `validate key` helper method?
}