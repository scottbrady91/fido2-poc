using System.Security.Cryptography;
using System.Text.Json.Nodes;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.Fido2.Cryptography;
using Xunit;

namespace ScottBrady.Fido2.Tests.Cryptography;

public class EcdsaCredentialPublicKeyTests
{
    private const string ExampleEcdsaJson = "{\"1\":2,\"3\":-7,\"-1\":1,\"-2\":\"sSV4_lv6YfTEWIo9KeXIbUu3DIxGd6eS3j55AW9h5Pw\",\"-3\":\"HEOhKFqBrULbgtM1mRkNFs8Nw_EGCuJVRgTgzieWMOk\"}";
    private const string ExampleRsaJson = "{\"1\":3,\"3\":-257,\"-1\":\"o3pemjl5EVYr5xYq0M7CPz5rk7XHNXlcWp662cmaaYUzZNvoyf8wKxNLshFJi1v9MBqZqF6Dq-F6fLbOV_LYBA7TlRKnHoo41dLiZMyQUOh7t6OM-5JD_cui3mMehn0jGzDxO1KoZLIiZaF13XFl8isMi3KXe0PGnirdCfo7w5zywUEcVeT7D8IixS5ywuINjZO3DK_f0ZEAG2_EcUf0_OjXcHFGcKWERh73JDI76Vknw-Q7XNCcnJAMn1I6zludMLMaUhi4SE1aj__t3MsIgIDOSXoGfi1aN89WgQgRFq3IxLM1hGjQKE1mwzRiw3nU_bnr1uIVtwXD9k4_g7kxO424dk2TOoXboy-0m33H1RyWgCm9ugCJWB4RP7HToriybZ6oeH8_X9AFD0vp_mDgI-bURpjUE0NIa_RU9WdpDHnUUt1q5cFiTpEKpXaZ4YgK27VIUtWM1hZJnXGB7Qi4NAOosVgwBecwzHzO9IQk0QP7CCll7ho-zxPbBJDAKZJ3\",\"-2\":\"AQAB\"}";

    [Fact]
    public void WhenInvalidJson_ExpectFidoException()
    {
        Assert.Throws<FidoException>(() => new CredentialPublicKey("<xml>wtf</xml>"));
    }

    [Fact]
    public void WhenInvalidEcKeyParameters_ExpectFidoException()
    {
        var jsonNode = JsonNode.Parse(ExampleEcdsaJson);
        jsonNode["-3"] = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(12));
        
        var invalidKey = new CredentialPublicKey(jsonNode.ToJsonString());
        
        var exception = Assert.Throws<FidoException>(() => invalidKey.LoadEcParameters());
        exception.InnerException.Should().BeOfType<CryptographicException>();

    }
    
    [Fact]
    public void WhenValidEcdsaKey_ExpectCorrectValues()
    {
        var key = new CredentialPublicKey(ExampleEcdsaJson);
        key.KeyType.Should().Be(CoseConstants.KeyTypes.Ec2);
        key.Algorithm.Should().Be(CoseConstants.Algorithms.ES256);
        key.KeyAsJson.Should().Be(ExampleEcdsaJson);

        var parameters = key.LoadEcParameters();
        parameters.Curve.IsNamed.Should().BeTrue();
        parameters.Curve.Oid.FriendlyName.Should().Be("nistP256");
        parameters.Q.X.Should().BeEquivalentTo(Base64UrlEncoder.DecodeBytes("sSV4_lv6YfTEWIo9KeXIbUu3DIxGd6eS3j55AW9h5Pw"));
        parameters.Q.Y.Should().BeEquivalentTo(Base64UrlEncoder.DecodeBytes("HEOhKFqBrULbgtM1mRkNFs8Nw_EGCuJVRgTgzieWMOk"));
    }
    
    [Fact]
    public void WhenValidRsaKey_ExpectCorrectValues()
    {
        var key = new CredentialPublicKey(ExampleRsaJson);
        key.KeyType.Should().Be(CoseConstants.KeyTypes.Rsa);
        key.Algorithm.Should().Be(CoseConstants.Algorithms.RS256);
        key.KeyAsJson.Should().Be(ExampleRsaJson);

        var parameters = key.LoadRsaParameters();
        parameters.Modulus.Should().BeEquivalentTo(Base64UrlEncoder.DecodeBytes("o3pemjl5EVYr5xYq0M7CPz5rk7XHNXlcWp662cmaaYUzZNvoyf8wKxNLshFJi1v9MBqZqF6Dq-F6fLbOV_LYBA7TlRKnHoo41dLiZMyQUOh7t6OM-5JD_cui3mMehn0jGzDxO1KoZLIiZaF13XFl8isMi3KXe0PGnirdCfo7w5zywUEcVeT7D8IixS5ywuINjZO3DK_f0ZEAG2_EcUf0_OjXcHFGcKWERh73JDI76Vknw-Q7XNCcnJAMn1I6zludMLMaUhi4SE1aj__t3MsIgIDOSXoGfi1aN89WgQgRFq3IxLM1hGjQKE1mwzRiw3nU_bnr1uIVtwXD9k4_g7kxO424dk2TOoXboy-0m33H1RyWgCm9ugCJWB4RP7HToriybZ6oeH8_X9AFD0vp_mDgI-bURpjUE0NIa_RU9WdpDHnUUt1q5cFiTpEKpXaZ4YgK27VIUtWM1hZJnXGB7Qi4NAOosVgwBecwzHzO9IQk0QP7CCll7ho-zxPbBJDAKZJ3"));
        parameters.Exponent.Should().BeEquivalentTo(Base64UrlEncoder.DecodeBytes("AQAB"));
    }
}
