using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.Fido2.Models;
using ScottBrady.Fido2.Parsers;
using ScottBrady.Fido2.Stores;

namespace ScottBrady.Fido2;

// https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
public class FidoRegistrationService
{
    private const string RpId = "localhost";
    private const string RpName = "SB test 23";
    private readonly AttestationObjectParser attestationObjectParser = new AttestationObjectParser();
    private readonly ClientDataParser clientDataParser = new ClientDataParser();
    private readonly IFidoKeyStore keyStore = new InMemoryFidoKeyStore();
    
    public FidoRegistrationOptions StartRegistration(FidoRegistrationRequest request)
    {
        // inputs: user
        // global: relying party
        // overrides: timeout, algs (PublicKeyCredentialParameters), excludeCredentials?, authenticatorSelection???, attestation preference, extensions (pass though?)
        
        var options = new FidoRegistrationOptions
        {
            RelyingParty = new RelyingParty
            {
                Id = RpId,
                Name = RpName
            },
            User = new User
            {
                Id = RandomNumberGenerator.GetBytes(32),
                Name = "Scott",
                DisplayName = "Scott Brady - test"
            },
            Challenge = RandomNumberGenerator.GetBytes(16)
        };
        
        // TODO: store options

        return options;
    }
    
    public void CompleteRegistration(ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> clientDataJson, ReadOnlySpan<byte> attestationObject)
    {
        var parsedClientData = clientDataParser.Parse(clientDataJson);
        if (parsedClientData.Type != "webauthn.create") throw new Exception();
        if (!Base64UrlEncoder.DecodeBytes(parsedClientData.Challenge).AsSpan().SequenceEqual(challenge)) throw new Exception(); // TODO: remove Microsoft.IdentityModel dependency
        if (parsedClientData.Origin != "https://localhost:5000") throw new Exception();
        if (parsedClientData.TokenBinding != null && parsedClientData.TokenBinding.Status == TokenBinding.TokenBindingStatus.Present) throw new Exception(); // unsupported 
        
        // TODO: hook for custom validation

        var parsedAttestationObject = attestationObjectParser.Parse(attestationObject);
        if (parsedAttestationObject.StatementFormat != "none") throw new Exception();
        if (parsedAttestationObject.Statement.Count != 0) throw new Exception();
        
        // var clientDataHash = SHA256.HashData(clientDataJson); // used for attestation statement validation
        // TODO: hook for attestation validation?

        if (!SHA256.HashData(Encoding.UTF8.GetBytes(RpId)).SequenceEqual(parsedAttestationObject.AuthenticatorData.RpIdHash)) throw new Exception();

        if (parsedAttestationObject.AuthenticatorData.UserPresent == false) throw new Exception();
        
        // requires full options support
        // TODO: check if user verified required
        // TODO: check if alg is allowed or was requested
        
        // TODO: validate extensions 🤷
        
        // requires store
        // TODO: validate credential ID is not registered to a different user (either fail or remove old registration)
        
        // store key
        keyStore.Store(new FidoKey
        {
            // TODO: UserId = ???
            CredentialId = parsedAttestationObject.AuthenticatorData.CredentialId,
            // TODO: DeviceFriendlyName = ???
            Counter = parsedAttestationObject.AuthenticatorData.SignCount,
            // TODO: CredentialAsJson = ???
            // TODO: Created
            // TODO: LastUsed 
        });

        // TODO: recommended to store transports alongside key (call getTransports()) to use in future allowCredentials options


    }
}