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
    /// <summary>
    /// Creates a CredentialPublicKey from a JSON string using COSE keys and values.
    /// </summary>
    /// <param name="coseKeyAsJson">A JSON string using COSE keys and Values. See <see cref="CoseConstants"/></param>
    /// <exception cref="FidoException">Unable to parse public key or find required values</exception>
    public CredentialPublicKey(string coseKeyAsJson)
    {
        var jsonNode = JsonNode.Parse(coseKeyAsJson);
        if (jsonNode == null) throw new FidoException("Unable to load public key json");
        
        KeyAsJson = coseKeyAsJson;
        KeyType = jsonNode[CoseConstants.Parameters.Kty]?.ToString() ?? throw new FidoException("Unable to find kty (1) value");
        Algorithm = jsonNode[CoseConstants.Parameters.Alg]?.ToString() ?? throw new FidoException("Unable to find alg (2) value");
    }
    
    // TODO: consider using ints, not strings (value is always a string, even if not in CBOR?)
    
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

    /// <summary>
    /// Creates a <see cref="ECParameters"/> from the JSON key using COSE keys and values.
    /// </summary>
    /// <returns><see cref="ECParameters"/> that can be used to create an instance of <see cref="ECDsa"/></returns>
    /// <exception cref="FidoException">Unable to parse public key or find required values</exception>
    public ECParameters LoadEcParameters()
    {
        // TODO: guards
        
        var jsonNode = JsonNode.Parse(KeyAsJson);
        if (jsonNode == null) throw new FidoException("Unable to load public key json");

        var crv = jsonNode[CoseConstants.Parameters.Crv]?.ToString() ?? throw new FidoException("Unable to find crv (-1) value for EC key");
        var x = jsonNode[CoseConstants.Parameters.X]?.ToString() ?? throw new FidoException("Unable to find x (-2) coordinate for EC key");
        var y = jsonNode[CoseConstants.Parameters.Y]?.ToString() ?? throw new FidoException("Unable to find y (-3) coordinate for EC key");
        
        // TODO: call validate ECParameters?
        return new ECParameters
        {
            Curve = ParseCurve(crv),
            Q = new ECPoint
            {
                X = Base64UrlEncoder.DecodeBytes(x),
                Y = Base64UrlEncoder.DecodeBytes(y)
            }
        };
    }

    private static ECCurve ParseCurve(string coseCurve) => coseCurve switch
    {
        CoseConstants.EllipticCurves.P256 => ECCurve.NamedCurves.nistP256,
        CoseConstants.EllipticCurves.P384 => ECCurve.NamedCurves.nistP384,
        CoseConstants.EllipticCurves.P521 => ECCurve.NamedCurves.nistP521,
        _ => throw new FidoException($"Unsupported EC curve with COSE value '{coseCurve}'")
    };

    public RSAParameters LoadRsaParameters()
    {
        // TODO: guards
        
        var jsonNode = JsonNode.Parse(KeyAsJson);
        if (jsonNode == null) throw new Exception("unable to load json");
        
        var modulus = jsonNode[CoseConstants.Parameters.N]?.ToString();
        var exponent = jsonNode[CoseConstants.Parameters.E]?.ToString();

        return new RSAParameters
        {
            Modulus = Base64UrlEncoder.DecodeBytes(modulus),
            Exponent = Base64UrlEncoder.DecodeBytes(exponent)
        };
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
        public const string EdDSA = "-8";
        public const string ES384 = "-35";
        public const string ES512 = "-36";
        public const string ES256K = "-47";
        public const string RS256 = "-257";
        public const string RS384 = "-258";
        public const string RS512 = "-259";
        public const string RS1 = "-65535";
    }

    // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
    public static class EllipticCurves
    {
        public const string P256 = "1";
        public const string P384 = "2";
        public const string P521 = "3";
        public const string X25519 = "4";
        public const string X448 = "5";
        public const string Ed25519 = "6";
        public const string Ed448 = "7";
        public const string Secp256k1 = "8";
    }
}