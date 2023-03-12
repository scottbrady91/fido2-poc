using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using ScottBrady.Fido2.Cryptography;
using ScottBrady.Fido2.Models;
using ScottBrady.Fido2.Stores;
using Xunit;

namespace ScottBrady.Fido2.Tests.Component;

public class ApiTests
{
    private const string Username = "Scott";
    private const string RelyingPartyId = "localhost";
    private const string RelyingPartyName = "SB -Test";
    private const string Origin = "https://localhost:5000";
    
    private static class RegistrationData
    {
        public static readonly byte[] Challenge = Convert.FromBase64String("mdKy0+Ttoju2mRHPT4tnCWuSlkqUcT3lDBoVSAWqDoE=");
        public static readonly byte[] CredentialId = Convert.FromBase64String("tClTtePAKX4lyZOuD+++EQPBWbSYc3jSim/o6hYK+mk=");
        
        public const string Id = "tClTtePAKX4lyZOuD---EQPBWbSYc3jSim_o6hYK-mk";
        public static readonly byte[] RawId = Convert.FromBase64String("tClTtePAKX4lyZOuD+++EQPBWbSYc3jSim/o6hYK+mk=");
        public const string Type = "public-key";
        public static readonly byte[] ClientDataJson = Convert.FromBase64String("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoibWRLeTAtVHRvanUybVJIUFQ0dG5DV3VTbGtxVWNUM2xEQm9WU0FXcURvRSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==");
        public static readonly byte[] AttestationObject = Convert.FromBase64String("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAILQpU7XjwCl+JcmTrg/vvhEDwVm0mHN40opv6OoWCvpppQECAyYgASFYIBMoxe7iyqby7GJpUq7N9jXV4VHsi9t+LiL8MFietKCIIlggT0EFWh7HvIpZfg70N90Ug4B2dTXCt8Xz+6OHL6tu/Ik=");
    }
    
    private static class AuthenticationData
    {
        public static readonly byte[] Challenge = Convert.FromBase64String("hTC/DTL4I5cXglwgkEBV+A==");
        public static readonly byte[] CredentialId = Convert.FromBase64String("boXuxyyEyBO0JAV1gvuC/oifQXhgj4cxLfA5sa+cnaA=");
        public const string PublicKey = "{\"1\":2,\"3\":-7,\"-1\":1,\"-2\":\"sSV4_lv6YfTEWIo9KeXIbUu3DIxGd6eS3j55AW9h5Pw\",\"-3\":\"HEOhKFqBrULbgtM1mRkNFs8Nw_EGCuJVRgTgzieWMOk\"}";
        
        public const string Id = "boXuxyyEyBO0JAV1gvuC_oifQXhgj4cxLfA5sa-cnaA";
        public static readonly byte[] RawId = Convert.FromBase64String("boXuxyyEyBO0JAV1gvuC/oifQXhgj4cxLfA5sa+cnaA=");
        public const string Type = "public-key";
        public static readonly byte[] AuthenticatorData = Convert.FromBase64String("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAQ==");
        public static readonly byte[] Signature = Convert.FromBase64String("MEYCIQDL8f+Vr0Z7JBo9IMZeafX9hCrOJX9fQ5pZkPGQQu+yAgIhAOuOPJjbDN+BlouGxJpPI9WpOZ0u/12E+liI8dD0PXug");
        public static readonly byte[] UserHandle = Convert.FromBase64String("B+VIZZkOHvvx7DEIcKQDo1pCYqZ6jqSI273+TOpGQow=");
        public static readonly byte[] ClientDataJson = Convert.FromBase64String("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaFRDX0RUTDRJNWNYZ2x3Z2tFQlYtQSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9");
    }

    private readonly JsonSerializerOptions jsonSerializerOptions = new JsonSerializerOptions
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new IntArrayJsonConverter() }
    };
    
    [Fact]
    public async Task Register_Options()
    {
        const string username = "new-user";
        
        using var client = CreateTestHost();
        
        // {"username":"new-user","authenticatorSelection":{"authenticatorAttachment":"","userVerification":"","attestation":"none"}}
        var optionsResponse = await client.PutAsJsonAsync("/fido/register", new FidoRegistrationRequest(username), jsonSerializerOptions);
        optionsResponse.IsSuccessStatusCode.Should().BeTrue();

        // Example:
        // {
        //   "rp":{"id":"localhost","name":"SB Test"},
        //   "user":{"id":[25,53,209,156,156,118,137,61,141,245,99,89,225,238,164,38,145,130,158,90,226,11,37,249,153,198,182,92,79,144,79,203],"displayName":"Scott","name":"Scott"},
        //   "challenge":[43,183,161,111,217,170,221,226,199,30,248,88,225,250,195,113,245,170,179,95,108,129,88,148,165,44,248,72,47,135,80,157],
        //   "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259}],
        //   "attestation":"none"
        // }
        var creationOptions = await optionsResponse.Content.ReadFromJsonAsync<PublicKeyCredentialCreationOptions>(jsonSerializerOptions);
        creationOptions.RelyingParty.Id.Should().Be(RelyingPartyId);
        creationOptions.RelyingParty.Name.Should().Be(RelyingPartyName);
        creationOptions.User.Id.Should().NotBeEmpty();
        creationOptions.User.Name.Should().Be(username);
        creationOptions.User.DisplayName.Should().Be(username);
        creationOptions.Challenge.Should().NotBeEmpty();
        creationOptions.PublicKeyCredentialParameters.Any(x => x.Algorithm.ToString() == CoseConstants.Algorithms.ES256).Should().BeTrue();
        creationOptions.PublicKeyCredentialParameters.Any(x => x.Algorithm.ToString() == CoseConstants.Algorithms.RS256).Should().BeTrue();
        creationOptions.Timeout.Should().BeNull();
        creationOptions.ExcludeCredentials.Should().BeEmpty();
        creationOptions.AuthenticatorSelectionCriteria.Should().BeNull();
        creationOptions.Attestation.Should().Be(WebAuthnConstants.AttestationConveyancePreference.None);
        creationOptions.Extensions.Should().BeNull();
        creationOptions.DeviceDisplayName.Should().BeNull();
    }

    [Fact]
    public async Task Register_Complete()
    {
        var userId = RandomNumberGenerator.GetBytes(32);
        
        var optionsStore = new InMemoryFidoOptionsStore();
        await optionsStore.Store(new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity(RelyingPartyId),
            new PublicKeyCredentialUserEntity(userId, Username, Username),
            RegistrationData.Challenge,
            new[] { new PublicKeyCredentialParameters { Type = WebAuthnConstants.PublicKeyCredentialType.PublicKey, Algorithm = int.Parse(CoseConstants.Algorithms.ES256) } }));

        using var client = CreateTestHost(services => services.AddScoped<IFidoOptionsStore>(_ => optionsStore));

        // {
        //   "id":"tClTtePAKX4lyZOuD---EQPBWbSYc3jSim_o6hYK-mk",
        //   "rawId":"tClTtePAKX4lyZOuD+++EQPBWbSYc3jSim/o6hYK+mk=",
        //   "type":"public-key",
        //   "response":{
        //     "attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAILQpU7XjwCl+JcmTrg/vvhEDwVm0mHN40opv6OoWCvpppQECAyYgASFYIBMoxe7iyqby7GJpUq7N9jXV4VHsi9t+LiL8MFietKCIIlggT0EFWh7HvIpZfg70N90Ug4B2dTXCt8Xz+6OHL6tu/Ik=",
        //     "clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoibWRLeTAtVHRvanUybVJIUFQ0dG5DV3VTbGtxVWNUM2xEQm9WU0FXcURvRSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ=="
        //   }
        // }
        var publicKeyCredential = new PublicKeyCredential(
            RegistrationData.Id,
            RegistrationData.RawId,
            RegistrationData.Type,
            new AuthenticatorAttestationResponse
            {
                AttestationObject = RegistrationData.AttestationObject,
                ClientDataJson = RegistrationData.ClientDataJson
            });

        var response = await client.PostAsync("/fido/register",
            new StringContent(JsonSerializer.Serialize(publicKeyCredential), Encoding.UTF8, "application/json"));

        response.IsSuccessStatusCode.Should().BeTrue();
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var createdKey = InMemoryFidoKeyStore.Keys.FirstOrDefault(x => x.UserId.SequenceEqual(userId));
        Assert.NotNull(createdKey);
        
        createdKey.UserId.Should().BeEquivalentTo(userId);
        createdKey.Username.Should().Be(Username);
        createdKey.CredentialId.Should().BeEquivalentTo(RegistrationData.CredentialId);
        createdKey.Counter.Should().Be(0);
        createdKey.DeviceFriendlyName.Should().BeNull();

        // {"1":2,"3":-7,"-1":1,"-2":"EyjF7uLKpvLsYmlSrs32NdXhUeyL234uIvwwWJ60oIg","-3":"T0EFWh7HvIpZfg70N90Ug4B2dTXCt8Xz-6OHL6tu_Ik"}
        createdKey.CredentialPublicKey.KeyType.Should().Be(CoseConstants.KeyTypes.Ec2);
        createdKey.CredentialPublicKey.Algorithm.Should().Be(CoseConstants.Algorithms.ES256);
        createdKey.CredentialPublicKey.KeyAsJson.Should().Be(
                "{\"1\":2,\"3\":-7,\"-1\":1,\"-2\":\"EyjF7uLKpvLsYmlSrs32NdXhUeyL234uIvwwWJ60oIg\",\"-3\":\"T0EFWh7HvIpZfg70N90Ug4B2dTXCt8Xz-6OHL6tu_Ik\"}");
        
        createdKey.Created.Should().BeWithin(TimeSpan.FromHours(1));
        createdKey.LastUsed.Should().BeWithin(TimeSpan.FromHours(1));
    }
    
    [Fact]
    public async Task Authenticate_Options()
    {
        const string username = "bob@example.com";
        var credentialId = RandomNumberGenerator.GetBytes(32);
        
        InMemoryFidoKeyStore.Keys.Add(new FidoKey
        {
            UserId = RandomNumberGenerator.GetBytes(16),
            Username = username,
            CredentialId = credentialId,
            Counter = 0,
            Created = DateTime.UtcNow.AddDays(-30), 
            LastUsed = DateTime.UtcNow.AddDays(-30),
            DeviceFriendlyName = "laptop"
        });
        
        using var client = CreateTestHost();
        
        // {"username":"Scott","authenticatorSelection":{"authenticatorAttachment":"","userVerification":"","attestation":"none"}}
        var optionsResponse = await client.PutAsJsonAsync("/fido/authenticate", new FidoAuthenticationRequest(username), jsonSerializerOptions);
        optionsResponse.IsSuccessStatusCode.Should().BeTrue();

        // Example:
        // {
        //   "rp":{"id":"localhost","name":"SB Test"},
        //   "user":{"id":[25,53,209,156,156,118,137,61,141,245,99,89,225,238,164,38,145,130,158,90,226,11,37,249,153,198,182,92,79,144,79,203],"displayName":"Scott","name":"Scott"},
        //   "challenge":[43,183,161,111,217,170,221,226,199,30,248,88,225,250,195,113,245,170,179,95,108,129,88,148,165,44,248,72,47,135,80,157],
        //   "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259}],
        //   "attestation":"none"
        // }
        var creationOptions = await optionsResponse.Content.ReadFromJsonAsync<PublicKeyCredentialRequestOptions>(jsonSerializerOptions);
        creationOptions.RpId.Should().Be(RelyingPartyId);
        creationOptions.Challenge.Should().NotBeEmpty();
        creationOptions.AllowCredentials.Should().Contain(x => x.Id.SequenceEqual(credentialId));
        creationOptions.UserVerification.Should().Be(WebAuthnConstants.UserVerificationRequirement.Preferred);
        creationOptions.Timeout.Should().BeNull();
        creationOptions.Extensions.Should().BeNull();
    }

    [Fact]
    public async Task Authenticate_Complete()
    {
        var optionsStore = new InMemoryFidoOptionsStore();
        await optionsStore.Store(new PublicKeyCredentialRequestOptions(AuthenticationData.Challenge)
            { AllowCredentials = new[] { new PublicKeyCredentialDescriptor(AuthenticationData.CredentialId) } });
        
        InMemoryFidoKeyStore.Keys.Add(new FidoKey
        {
            UserId = AuthenticationData.UserHandle,
            Username = Username,
            CredentialId = AuthenticationData.CredentialId,
            CredentialPublicKey = new CredentialPublicKey(AuthenticationData.PublicKey),
            Counter = 0,
            Created = DateTime.UtcNow.AddDays(-30), 
            LastUsed = DateTime.UtcNow.AddDays(-30),
            DeviceFriendlyName = "laptop"
        });
        
        using var client = CreateTestHost(services => services.AddScoped<IFidoOptionsStore>(_ => optionsStore));

        // {
        //   "id":"boXuxyyEyBO0JAV1gvuC_oifQXhgj4cxLfA5sa-cnaA",
        //   "rawId":"boXuxyyEyBO0JAV1gvuC/oifQXhgj4cxLfA5sa+cnaA=",
        //   "type":"public-key",
        //   "response":{
        //     "authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAQ==",
        //     "signature":"MEYCIQDL8f+Vr0Z7JBo9IMZeafX9hCrOJX9fQ5pZkPGQQu+yAgIhAOuOPJjbDN+BlouGxJpPI9WpOZ0u/12E+liI8dD0PXug",
        //     "userHandle":"B+VIZZkOHvvx7DEIcKQDo1pCYqZ6jqSI273+TOpGQow=",
        //     "clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaFRDX0RUTDRJNWNYZ2x3Z2tFQlYtQSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
        //   }
        // }
        var publicKeyCredential = new PublicKeyCredential(
            AuthenticationData.Id,
            AuthenticationData.RawId,
            AuthenticationData.Type,
            new AuthenticatorAssertionResponse
            {
                AuthenticatorData = AuthenticationData.AuthenticatorData,
                Signature = AuthenticationData.Signature,
                UserHandle = AuthenticationData.UserHandle,
                ClientDataJson = AuthenticationData.ClientDataJson
            });

        var response = await client.PostAsync("/fido/authenticate",
            new StringContent(JsonSerializer.Serialize(publicKeyCredential, jsonSerializerOptions), Encoding.UTF8, "application/json"));

        response.IsSuccessStatusCode.Should().BeTrue();
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var createdKey = InMemoryFidoKeyStore.Keys.FirstOrDefault(x => x.UserId.SequenceEqual(AuthenticationData.UserHandle));
        Assert.NotNull(createdKey);
        
        createdKey.Counter.Should().NotBe(0);
        createdKey.LastUsed.Should().BeWithin(TimeSpan.FromHours(1));

    }

    private static HttpClient CreateTestHost(Action<IServiceCollection> configureServices = null)
    {
        var application = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseContentRoot(Directory.GetCurrentDirectory());
                builder.ConfigureServices(services =>
                {
                    services.AddWebAuthn(options =>
                    {
                        options.RelyingPartyId = RelyingPartyId;
                        options.RelyingPartyName = RelyingPartyName;
                        options.RelyingPartyOrigin = Origin;
                    }).AddInMemoryKeyStore();

                    configureServices?.Invoke(services);
                });
            });
        
        return application.CreateClient();
    }
}