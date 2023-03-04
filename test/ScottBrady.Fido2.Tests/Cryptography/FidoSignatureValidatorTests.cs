using System.Collections.Generic;
using System.Text.Json;
using AutoFixture;
using ScottBrady.Fido2.Cryptography;
using ScottBrady.Fido2.Models;
using Xunit;

namespace ScottBrady.Fido2.Tests.Cryptography;

public class FidoSignatureValidatorTests
{
    private readonly FidoSignatureValidator sut = new FidoSignatureValidator();
    
    [Fact]
    public void HasValidSignature_WhenAlgorithmUnsupported_ExpectFidoException()
    {
        var response = new Fixture().Create<AuthenticatorAssertionResponse>();
        var key = CreateTestKey("9999", "9999");

        Assert.ThrowsAsync<FidoException>(() => sut.HasValidSignature(response, key));
    }

    private static CredentialPublicKey CreateTestKey(string kty, string alg)
    {
        var coseKey = new Dictionary<string, string>
        {
            { CoseConstants.Parameters.Kty, kty },
            { CoseConstants.Parameters.Alg, alg }
        };

        return new CredentialPublicKey(JsonSerializer.Serialize(coseKey));
    }
}