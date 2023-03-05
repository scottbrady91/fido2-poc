using System;
using FluentAssertions;
using ScottBrady.Fido2.Parsers;
using Xunit;

namespace ScottBrady.Fido2.Tests;

/// <summary>
/// Basic happy path tests using data from Windows Hello.
/// </summary>
public class HappyPathTests
{
    private static class RegistrationData
    {
        public static readonly byte[] TestClientDataJson = Convert.FromBase64String("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVjJwUlduTE94Yi03UV9WYzVCNDk1USIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9");
        public static readonly byte[] TestAttestationObject = Convert.FromBase64String("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAICVrJnYJupd8EWxwKQVuGJuh6RrCDEYDMvlND9ww67qRpQECAyYgASFYIID3OZq4HO2dCKLVsbYoCdwSAhgcoxnMBPV5Si0ryBaMIlggoXBwitSsaA4PKUEIfMAHcDQLFgkgqdqNZMcJ3gXKETY=");
    }

    private const string Origin = "https://localhost:5000";

    [Fact]
    public void ClientDataParser_Parse()
    {
        var sut = new ClientDataParser();
        var clientData = sut.Parse(RegistrationData.TestClientDataJson);

        clientData.Type.Should().Be("webauthn.create");
        clientData.Origin.Should().Be(Origin);
        clientData.Challenge.Should().Be("V2pRWnLOxb-7Q_Vc5B495Q");
        clientData.CrossOrigin.Should().Be(false);
    }

    [Fact]
    public void AttestationObjectParser_Parse()
    {
        var sut = new AttestationObjectParser(new AuthenticatorDataParser());
        var attestationObject = sut.Parse(RegistrationData.TestAttestationObject);
        
        attestationObject.StatementFormat.Should().Be("none");
        attestationObject.Statement.Length.Should().Be(1);

        attestationObject.AuthenticatorData.RpIdHash.Should().BeEquivalentTo(Convert.FromBase64String("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2M="));
        attestationObject.AuthenticatorData.UserPresent.Should().BeTrue();
        attestationObject.AuthenticatorData.UserVerified.Should().BeTrue();
        attestationObject.AuthenticatorData.AttestedCredentialDataIncluded.Should().BeTrue();
        attestationObject.AuthenticatorData.ExtensionDataIncluded.Should().BeFalse();
        attestationObject.AuthenticatorData.SignCount.Should().Be(0);

        attestationObject.AuthenticatorData.Aaguid.Should().BeEquivalentTo(Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAA=="));
        attestationObject.AuthenticatorData.CredentialId.Should().BeEquivalentTo(Convert.FromBase64String("JWsmdgm6l3wRbHApBW4Ym6HpGsIMRgMy+U0P3DDrupE="));
        attestationObject.AuthenticatorData.CredentialPublicKey.KeyAsJson.Should().Be(
            "{\"1\":2,\"3\":-7,\"-1\":1,\"-2\":\"gPc5mrgc7Z0IotWxtigJ3BICGByjGcwE9XlKLSvIFow\",\"-3\":\"oXBwitSsaA4PKUEIfMAHcDQLFgkgqdqNZMcJ3gXKETY\"}");

        attestationObject.AuthenticatorData.Extensions.Should().BeNull();
    }
}