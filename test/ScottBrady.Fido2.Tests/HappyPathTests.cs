﻿using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Options;
using ScottBrady.Fido2.Cryptography;
using ScottBrady.Fido2.Models;
using ScottBrady.Fido2.Parsers;
using ScottBrady.Fido2.Stores;
using Xunit;

namespace ScottBrady.Fido2.Tests;

/// <summary>
/// Basic happy path tests using data from Windows Hello.
/// </summary>
public class HappyPathTests
{
    private static class RegistrationData
    {
        public static readonly byte[] TestChallenge = Convert.FromBase64String("V2pRWnLOxb+7Q/Vc5B495Q==");
        public static readonly byte[] TestClientDataJson = Convert.FromBase64String("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVjJwUlduTE94Yi03UV9WYzVCNDk1USIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9");
        public static readonly byte[] TestAttestationObject = Convert.FromBase64String("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAICVrJnYJupd8EWxwKQVuGJuh6RrCDEYDMvlND9ww67qRpQECAyYgASFYIID3OZq4HO2dCKLVsbYoCdwSAhgcoxnMBPV5Si0ryBaMIlggoXBwitSsaA4PKUEIfMAHcDQLFgkgqdqNZMcJ3gXKETY=");
    }

    private static class AuthenticationData
    {
        public const string TestCredential = "{\"1\":2,\"3\":-7,\"-1\":1,\"-2\":\"sSV4_lv6YfTEWIo9KeXIbUu3DIxGd6eS3j55AW9h5Pw\",\"-3\":\"HEOhKFqBrULbgtM1mRkNFs8Nw_EGCuJVRgTgzieWMOk\"}";
        public const string TestId = "boXuxyyEyBO0JAV1gvuC_oifQXhgj4cxLfA5sa-cnaA";
        public static readonly byte[] TestRawId = Convert.FromBase64String("boXuxyyEyBO0JAV1gvuC/oifQXhgj4cxLfA5sa+cnaA=");
        public static readonly byte[] TestChallenge = Convert.FromBase64String("hTC/DTL4I5cXglwgkEBV+A==");
        public static readonly byte[] TestAuthenticatorData = Convert.FromBase64String("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAQ==");
        public static readonly byte[] TestSignature = Convert.FromBase64String("MEYCIQDL8f+Vr0Z7JBo9IMZeafX9hCrOJX9fQ5pZkPGQQu+yAgIhAOuOPJjbDN+BlouGxJpPI9WpOZ0u/12E+liI8dD0PXug");
        public static readonly byte[] TestUserHandle = Convert.FromBase64String("B+VIZZkOHvvx7DEIcKQDo1pCYqZ6jqSI273+TOpGQow=");
        public static readonly byte[] TestClientDataJson = Convert.FromBase64String("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaFRDX0RUTDRJNWNYZ2x3Z2tFQlYtQSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9");
    }

    private const string RelyingPartyId = "localhost";
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
        attestationObject.Statement.Values.Any().Should().BeFalse();

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

    [Fact]
    public async Task FidoRegistrationService_CompleteRegistration()
    {
        var optionsStore = new InMemoryFidoOptionsStore();
        await optionsStore.Store(new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity(RelyingPartyId),
            new PublicKeyCredentialUserEntity(RandomNumberGenerator.GetBytes(32), "Scott", "Scott"),
            RegistrationData.TestChallenge,
            new[] { new PublicKeyCredentialParameters { Type = WebAuthnConstants.PublicKeyCredentialType.PublicKey, Algorithm = int.Parse(CoseConstants.Algorithms.ES256) } }));

        var sut = new FidoRegistrationService(
            new ClientDataParser(),
            new AttestationObjectParser(new AuthenticatorDataParser()),
            optionsStore,
            new InMemoryFidoKeyStore(),
            new OptionsWrapper<FidoOptions>(new FidoOptions { RelyingPartyId = RelyingPartyId }));
        
        await sut.Complete(new PublicKeyCredential
        {
            Type = WebAuthnConstants.PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAttestationResponse
            {
                AttestationObject = RegistrationData.TestAttestationObject,
                ClientDataJson = RegistrationData.TestClientDataJson
            }
            
        });
    }

    [Fact]
    public async Task FidoAuthenticationService_CompleteRegistration()
    {
        var optionsStore = new InMemoryFidoOptionsStore();
        await optionsStore.Store(new PublicKeyCredentialRequestOptions(AuthenticationData.TestChallenge));

        var keyStore = new InMemoryFidoKeyStore();
        await keyStore.Store(new FidoKey
        {
            UserId = AuthenticationData.TestUserHandle,
            CredentialId = AuthenticationData.TestRawId,
            CredentialPublicKey = new CredentialPublicKey(AuthenticationData.TestCredential),
            Counter = 0
        });

        var sut = new FidoAuthenticationService(
            optionsStore,
            new FidoSignatureValidator(new OptionsWrapper<FidoOptions>(new FidoOptions { RelyingPartyId = RelyingPartyId })),
            keyStore,
            new OptionsWrapper<FidoOptions>(new FidoOptions { RelyingPartyId = RelyingPartyId }));
        
        await sut.Complete(new PublicKeyCredential
        {
            Id = AuthenticationData.TestId,
            RawId = AuthenticationData.TestRawId,
            Type = WebAuthnConstants.PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAssertionResponse
            {
                AuthenticatorData = AuthenticationData.TestAuthenticatorData,
                Signature = AuthenticationData.TestSignature,
                UserHandle = AuthenticationData.TestUserHandle,
                ClientDataJson = AuthenticationData.TestClientDataJson
            }
            
        });
    }
}