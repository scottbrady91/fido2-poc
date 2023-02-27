
using System.Text.Json.Nodes;

namespace ScottBrady.Fido2.Cryptography;

public class CredentialPublicKey
{
    public CredentialPublicKey(string coseKeyAsJson)
    {
        var jsonNode = JsonNode.Parse(coseKeyAsJson);
        if (jsonNode == null) throw new FidoException("Unable to load public key");
        
        KeyType = jsonNode[CoseParameters.Kty]?.ToString();
        KeyId = jsonNode[CoseParameters.Kid]?.ToString();
        Algorithm = jsonNode[CoseParameters.Alg]?.ToString();
    }
    
    public string KeyType { get; }

    public string KeyId { get; }
    
    public string Algorithm { get; }

}


public class EcdsaCredentialPublicKey : CredentialPublicKey
{
    public EcdsaCredentialPublicKey(string coseKeyAsJson) : base(coseKeyAsJson)
    {
        var jsonNode = JsonNode.Parse("");
    }
    
    public string Curve { get; set; }

    public string X { get; set; }

    public string Y { get; set; }
}

// https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
// https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
public static class CoseParameters
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

// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
public static class CoseAlgorithms
{
    public const string ES256 = "-7";
}