using FluentAssertions;
using ScottBrady.Fido2.Models;
using ScottBrady.Fido2.Parsers;
using ScottBrady.Fido2.Stores;
using Xunit;

namespace ScottBrady.Fido2.Tests;

// Basic happy path tests using data from Windows Hello
public class HappyPathTests
{
    private readonly byte[] testChallenge = Convert.FromBase64String("V2pRWnLOxb+7Q/Vc5B495Q==");
    private readonly byte[] testClientDataJson = Convert.FromBase64String("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVjJwUlduTE94Yi03UV9WYzVCNDk1USIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9");
    private readonly byte[] testAttestationObject = Convert.FromBase64String("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAICVrJnYJupd8EWxwKQVuGJuh6RrCDEYDMvlND9ww67qRpQECAyYgASFYIID3OZq4HO2dCKLVsbYoCdwSAhgcoxnMBPV5Si0ryBaMIlggoXBwitSsaA4PKUEIfMAHcDQLFgkgqdqNZMcJ3gXKETY=");
    
    [Fact]
    public void ClientDataParser_Parse()
    {
        var sut = new ClientDataParser();
        var clientData = sut.Parse(testClientDataJson);

        clientData.Type.Should().Be("webauthn.create");
        clientData.Origin.Should().Be("https://localhost:5000");
        clientData.Challenge.Should().Be("V2pRWnLOxb-7Q_Vc5B495Q");
        clientData.CrossOrigin.Should().Be(false);
    }

    [Fact]
    public void AttestationObjectParser_Parse()
    {
        var sut = new AttestationObjectParser();
        var attestationObject = sut.Parse(testAttestationObject);
        
        attestationObject.StatementFormat.Should().Be("none");
        attestationObject.Statement.Values.Any().Should().BeFalse();

        attestationObject.AuthenticatorData.RpIdHash.Should().BeEquivalentTo(Convert.FromBase64String("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2M="));
        attestationObject.AuthenticatorData.UserPresent.Should().BeTrue();
        attestationObject.AuthenticatorData.UserVerified.Should().BeTrue();
        attestationObject.AuthenticatorData.AttestedCredentialDataIncluded.Should().BeTrue();
        attestationObject.AuthenticatorData.ExtensionDataIncluded.Should().BeFalse();
        attestationObject.AuthenticatorData.SignCount.Should().Be(0);

        attestationObject.AuthenticatorData.Aaguid.Should().BeEquivalentTo(Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAA=="));
        attestationObject.AuthenticatorData.CredentialId.Should().BeEquivalentTo(Convert.FromBase64String("JWsmdgm6l3wRbHApBW4Ym6HpGsIMRgMy+U0P3DDrupE="));
        attestationObject.AuthenticatorData.CredentialPublicKeyAsJson.Should().Be(
            "{\"1\":2,\"3\":-7,\"-1\":1,\"-2\":\"gPc5mrgc7Z0IotWxtigJ3BICGByjGcwE9XlKLSvIFow\",\"-3\":\"oXBwitSsaA4PKUEIfMAHcDQLFgkgqdqNZMcJ3gXKETY\"}");

        attestationObject.AuthenticatorData.Extensions.Should().BeNull();
    }

    [Fact]
    public void FidoRegistrationService_CompleteRegistration()
    {
        var optionsStore = new InMemoryFidoOptionsStore();
        optionsStore.Store(new PublicKeyCredentialCreationOptions { Challenge = testChallenge });
        var sut = new FidoRegistrationService(optionsStore);
        
        sut.Complete(testClientDataJson, testAttestationObject);
    }
}