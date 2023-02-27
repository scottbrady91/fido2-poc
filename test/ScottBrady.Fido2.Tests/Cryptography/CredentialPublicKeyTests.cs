using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace ScottBrady.Fido2.Tests.Cryptography;

public class CredentialPublicKeyTests
{
    private const string ExampleEcdsaJson = "{\"1\":2,\"3\":-7,\"-1\":1,\"-2\":\"sSV4_lv6YfTEWIo9KeXIbUu3DIxGd6eS3j55AW9h5Pw\",\"-3\":\"HEOhKFqBrULbgtM1mRkNFs8Nw_EGCuJVRgTgzieWMOk\"}";
    private const string ExampleRsaJson = "";

    [Fact]
    public void ctor_json_WhenEcdsaKey_ExpectCorrectValues()
    {
        // var key = JsonSerializer.Deserialize<CredentialPublicKey>(ExampleEcdsaJson);

        var jObject = JsonObject.Parse(ExampleEcdsaJson);
        var value = jObject["1"].ToString();
    }
}