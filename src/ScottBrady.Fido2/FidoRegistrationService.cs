using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.Fido2.Parsers;

namespace ScottBrady.Fido2;

// https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
public class FidoRegistrationService
{
    private const string RpId = "localhost";
    private readonly AttestationObjectParser attestationObjectParser = new AttestationObjectParser();
    private readonly ClientDataParser clientDataParser = new ClientDataParser();
    
    public void CompleteRegistration(ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> clientDataJson, ReadOnlySpan<byte> attestationObject)
    {
        var parsedClientData = clientDataParser.Parse(clientDataJson);
        if (parsedClientData.Type != "webauthn.create") throw new Exception();
        if (!Base64UrlEncoder.DecodeBytes(parsedClientData.Challenge).AsSpan().SequenceEqual(challenge)) throw new Exception();
        if (parsedClientData.Origin != "https://localhost:5000") throw new Exception();
        // TODO: if (parsedClientData.TokenBinding)
        
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
        
        // TODO: store key (id, pubkey, counter)
        // TODO: recommended to store transports alongside key (call getTransports()) to use in future allowCredentials options
        
        
    }
}