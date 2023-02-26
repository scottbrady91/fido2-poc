﻿using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.Fido2.Cryptography;

public class FidoSignatureValidator
{
    private IEnumerable<ISignatureValidationStrategy> validators = new List<ISignatureValidationStrategy>();

    public Task ValidateSignature(byte[] data, byte[] signature, string keyAsJson)
    {
        var jsonNode = JsonNode.Parse(keyAsJson);
        var kty = jsonNode["1"]?.GetValue<int>();
        
        // TODO: parse key (deserialize and validate in validator)
        
        // TODO: move signature concatenation here?

        // TODO: get correct strategy
        ISignatureValidationStrategy strategy = kty == 2 ? new EcdsaSignatureValidationStrategy() : new RsaSignatureValidationStrategy();
        
        // TODO: validate signature
        var isValid = strategy.ValidateSignature(data, signature, keyAsJson);
        if (!isValid) throw new Exception("sig issue");

        return Task.CompletedTask;
    }
}

public interface ISignatureValidationStrategy
{
    bool ValidateSignature(ReadOnlySpan<byte> data, byte[] signature, string keyAsJson);
}

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

public class RsaSignatureValidationStrategy : ISignatureValidationStrategy
{
    public bool ValidateSignature(ReadOnlySpan<byte> data, byte[] signature, string keyAsJson)
    {
        var jsonNode = JsonNode.Parse(keyAsJson);
        if (jsonNode == null) throw new Exception("unable to load json");
        
        var kty = jsonNode["1"]?.GetValue<int>(); // TODO: pull COSE keys into constants
        var alg = jsonNode["3"]?.GetValue<int>();
        
        var modulus = jsonNode["-1"]?.GetValue<string>();
        var exponent = jsonNode["-2"]?.GetValue<string>();
        
        var parameters = new RSAParameters
        {
            Modulus = Base64UrlEncoder.DecodeBytes(modulus),
            Exponent = Base64UrlEncoder.DecodeBytes(exponent)
        };

        using var rsa = RSA.Create(parameters);
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}