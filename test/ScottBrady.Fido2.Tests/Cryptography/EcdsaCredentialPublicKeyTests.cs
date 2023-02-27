using System.Text.Json;
using System.Text.Json.Serialization;
using FluentAssertions;

using ScottBrady.Fido2.Cryptography;
using Xunit;
using JsonSerializer = System.Text.Json.JsonSerializer;

namespace ScottBrady.Fido2.Tests.Cryptography;

public class EcdsaCredentialPublicKeyTests
{
    private const string ExampleEcdsaJson = "{\"1\":2,\"3\":-7,\"-1\":1,\"-2\":\"sSV4_lv6YfTEWIo9KeXIbUu3DIxGd6eS3j55AW9h5Pw\",\"-3\":\"HEOhKFqBrULbgtM1mRkNFs8Nw_EGCuJVRgTgzieWMOk\"}";

    private readonly TestKey testKey = new TestKey
    {
        KeyType = CoseConstants.KeyTypes.Ec2,
        Algorithm = CoseConstants.Algorithms.ES256,
        // CustomKeyParam1 = 
    };

    [Fact]
    public void ctor_WhenValidEcdsaKey_ExpectCorrectValues()
    {
        var json = testKey.ToCoseJson();
        
    }
    
    [Fact]
    public void ctor_WhenRealEcdsaKey_ExpectCorrectValues()
    {
        var key = new CredentialPublicKey(ExampleEcdsaJson);
        key.KeyType.Should().Be(CoseConstants.KeyTypes.Ec2);
        key.Algorithm.Should().Be(CoseConstants.Algorithms.ES256);
        
    }
}

public class TestKey
{
    [JsonPropertyName(CoseConstants.Parameters.Kty)]
    public string KeyType { get; set; }
    
    [JsonPropertyName(CoseConstants.Parameters.Alg)]
    public string Algorithm { get; set; }
    
    [JsonPropertyName("-1")] // e.g. crv or n
    public string CustomKeyParam1 { get; set; }
    
    [JsonPropertyName("-2")] // e.g. x or e
    public string CustomKeyParam2 { get; set; }
    
    [JsonPropertyName("-3")] // e.g. y
    public string CustomKeyParam3 { get; set; }

    public string ToCoseJson() =>
        JsonSerializer.Serialize(this, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
}