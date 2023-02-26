using System;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.Fido2.Cryptography;

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