
using System;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.Fido2.Cryptography;

/// <summary>
/// A COSE public key.
/// </summary>
public class CredentialPublicKey
{
    public CredentialPublicKey(string coseKeyAsJson)
    {
        var jsonNode = JsonNode.Parse(coseKeyAsJson);
        if (jsonNode == null) throw new FidoException("Unable to load public key");
        
        KeyAsJson = coseKeyAsJson;
        KeyType = jsonNode[CoseConstants.Parameters.Kty]?.ToString();
        Algorithm = jsonNode[CoseConstants.Parameters.Alg]?.ToString();
    }
    
    /// <summary>
    /// The COSE key type.
    /// </summary>
    public string KeyType { get; }

    /// <summary>
    /// The COSE algorithm type.
    /// </summary>
    public string Algorithm { get; }
    
    /// <summary>
    /// The original COSE key as json.
    /// </summary>
    public string KeyAsJson { get; }

    public ECDsa ToEcdsa()
    {
        // TODO: guards
        
        var jsonNode = JsonNode.Parse(KeyAsJson);
        if (jsonNode == null) throw new Exception("unable to load json");

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

        return ECDsa.Create(parameters);
    }

    public RSA ToRsa()
    {
        // TODO: guards
        
        var jsonNode = JsonNode.Parse(KeyAsJson);
        if (jsonNode == null) throw new Exception("unable to load json");
        
        var modulus = jsonNode["-1"]?.GetValue<string>();
        var exponent = jsonNode["-2"]?.GetValue<string>();
        
        var parameters = new RSAParameters
        {
            Modulus = Base64UrlEncoder.DecodeBytes(modulus),
            Exponent = Base64UrlEncoder.DecodeBytes(exponent)
        };

        return RSA.Create(parameters);
    }
}

public static class CoseConstants
{
    // https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
    // https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
    public static class Parameters
    {
        public const string Kty = "1";
        public const string Kid = "2";
        public const string Alg = "3";

        public const string Crv = "-1";
        public const string X = "-2";
        public const string Y = "-3";

        public const string N = "-1";
        public const string E = "-2";
    }

    // https://www.iana.org/assignments/cose/cose.xhtml#key-type
    public static class KeyTypes
    {
        public const string Okp = "1";
        public const string Ec2 = "2";
        public const string Rsa = "3";
        public const string Symmetric = "4";
        public const string HssLms = "5";
        public const string WalnutDsa = "6";
    }

    // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    public static class Algorithms
    {
        public const string ES256 = "-7";
    }
}