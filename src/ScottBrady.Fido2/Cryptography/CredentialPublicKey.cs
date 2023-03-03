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
        if (coseKeyAsJson == null) throw new ArgumentNullException(nameof(coseKeyAsJson));
        KeyAsJson = coseKeyAsJson;
        
        JsonNode jsonNode;
        try
        {
            jsonNode = JsonNode.Parse(coseKeyAsJson);
        }
        catch (Exception e)
        {
            throw new FidoException("Unable to parse coseKeyAsJson", e);
        }
        
        if (jsonNode == null) throw new FidoException("Unable to parse coseKeyAsJson");
        KeyType = jsonNode[CoseConstants.Parameters.Kty]?.ToString() ?? throw new FidoException("Unable to find kty (1) value");
        Algorithm = jsonNode[CoseConstants.Parameters.Alg]?.ToString() ?? throw new FidoException("Unable to find alg (2) value");
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

    /// <summary>
    /// Creates a <see cref="ECParameters"/> from the JSON key using COSE keys and values.
    /// </summary>
    /// <returns><see cref="ECParameters"/> that can be used to create an instance of <see cref="ECDsa"/></returns>
    /// <exception cref="FidoException">Unable to parse public key or find required values</exception>
    public ECParameters LoadEcParameters()
    {
        var jsonNode = JsonNode.Parse(KeyAsJson);
        if (jsonNode == null) throw new FidoException("Unable to parse coseKeyAsJson");

        var crv = jsonNode[CoseConstants.Parameters.Crv]?.ToString() ?? throw new FidoException("Unable to find crv (-1) value for EC key");
        var x = jsonNode[CoseConstants.Parameters.X]?.ToString() ?? throw new FidoException("Unable to find x (-2) coordinate for EC key");
        var y = jsonNode[CoseConstants.Parameters.Y]?.ToString() ?? throw new FidoException("Unable to find y (-3) coordinate for EC key");
        
        var parameters = new ECParameters
        {
            Curve = ParseCurve(crv),
            Q = new ECPoint
            {
                X = Base64UrlEncoder.DecodeBytes(x),
                Y = Base64UrlEncoder.DecodeBytes(y)
            }
        };

        try
        {
            parameters.Validate();
        }
        catch (Exception e)
        {
            throw new FidoException("Invalid EC key", e);
        }

        return parameters;
    }

    private static ECCurve ParseCurve(string coseCurve) => coseCurve switch
    {
        CoseConstants.EllipticCurves.P256 => ECCurve.NamedCurves.nistP256,
        CoseConstants.EllipticCurves.P384 => ECCurve.NamedCurves.nistP384,
        CoseConstants.EllipticCurves.P521 => ECCurve.NamedCurves.nistP521,
        _ => throw new FidoException($"Unsupported EC curve with COSE value '{coseCurve}'")
    };

    /// <summary>
    /// Creates a <see cref="RSAParameters"/> from the JSON key using COSE keys and values.
    /// </summary>
    /// <returns><see cref="RSAParameters"/> that can be used to create an instance of <see cref="RSA"/></returns>
    /// <exception cref="FidoException">Unable to parse public key or find required values</exception>
    public RSAParameters LoadRsaParameters()
    {
        var jsonNode = JsonNode.Parse(KeyAsJson);
        if (jsonNode == null) throw new FidoException("Unable to parse coseKeyAsJson");
        
        var modulus = jsonNode[CoseConstants.Parameters.N]?.ToString() ?? throw new FidoException("Unable to find modulus (-1) value for RSA key");
        var exponent = jsonNode[CoseConstants.Parameters.E]?.ToString() ?? throw new FidoException("Unable to find exponent (-2) value for RSA key");

        return new RSAParameters
        {
            Modulus = Base64UrlEncoder.DecodeBytes(modulus),
            Exponent = Base64UrlEncoder.DecodeBytes(exponent)
        };
    }
}