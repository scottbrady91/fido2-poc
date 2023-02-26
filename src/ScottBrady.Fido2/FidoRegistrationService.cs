using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
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

    private readonly IFidoOptionsStore optionsStore;
    private readonly IFidoKeyStore keyStore = new InMemoryFidoKeyStore();

    public FidoRegistrationService(IFidoOptionsStore optionsStore)
    {
        this.optionsStore = optionsStore ?? throw new ArgumentNullException(nameof(optionsStore));
    }
    
    public async Task<PublicKeyCredentialCreationOptions> Initiate(FidoRegistrationRequest request)
    {
        // TODO: global: relying party
        // TODO: overrides: timeout, algs (PublicKeyCredentialParameters), excludeCredentials?, authenticatorSelection???, attestation preference, extensions (pass though?)

        var options = new PublicKeyCredentialCreationOptions
        {
            Rp = new PublicKeyCredentialRpEntity
            {
                Id = RpId,
                Name = RpName
            },
            User = new PublicKeyCredentialUserEntity
            {
                Id = RandomNumberGenerator.GetBytes(32),
                Name = request.Username,
                DisplayName = request.UserDisplayName
            },
            Challenge = RandomNumberGenerator.GetBytes(32),
            DeviceDisplayName = request.DeviceDisplayName
        };
        
        await optionsStore.Store(options);

        return options;
    }
    
    public async Task Complete(PublicKeyCredential credential)
    {
        if (credential.Response is not AuthenticatorAttestationResponse response) throw new Exception("Incorrect response");
        var clientData = clientDataParser.Parse(response.ClientDataJson);

        // TODO: remove Microsoft.IdentityModel dependency
        var challenge = Base64UrlEncoder.DecodeBytes(clientData.Challenge);
        var options = await optionsStore.TakeRegistrationOptions(challenge);
        if (options == null) throw new Exception("Incorrect options");
        
        if (clientData.Type != "webauthn.create") throw new Exception("Incorrect type");
        if (!challenge.SequenceEqual(options.Challenge)) throw new Exception("Incorrect challenge");
        if (clientData.Origin != "https://localhost:5000") throw new Exception("Incorrect origin");
        if (clientData.TokenBinding != null && clientData.TokenBinding.Status == FidoConstants.TokenBindingStatus.Present) throw new Exception("Incorrect token binding"); 
        
        // TODO: hook for custom validation

        var attestationObject = attestationObjectParser.Parse(response.AttestationObject);
        if (attestationObject.StatementFormat != "none") throw new Exception("Incorrect statement format");
        if (attestationObject.Statement.Count != 0) throw new Exception("Incorrect statement count");
        
        // var clientDataHash = SHA256.HashData(clientDataJson); // used for attestation statement validation
        // TODO: hook for attestation validation?

        if (!SHA256.HashData(Encoding.UTF8.GetBytes(RpId)).SequenceEqual(attestationObject.AuthenticatorData.RpIdHash)) throw new Exception("Incorrect RP ID");

        if (attestationObject.AuthenticatorData.UserPresent == false) throw new Exception("Incorrect user present");
        
        // requires full options support
        // TODO: check if user verified required
        // TODO: check if alg is allowed or was requested
        
        // TODO: hook to validate extensions?
        
        // validate credential ID is not registered to a different user (either fail or remove old registration)
        var existingCredential = await keyStore.GetByCredentialId(attestationObject.AuthenticatorData.CredentialId);
        if (existingCredential != null) throw new Exception("Incorrect credential ID");

        // TODO: validate credential alg is supported by library
        
        // store key
        await keyStore.Store(new FidoKey
        {
            UserId = options.User.Id,
            DeviceFriendlyName = options.DeviceDisplayName,
            CredentialId = attestationObject.AuthenticatorData.CredentialId,
            Counter = attestationObject.AuthenticatorData.SignCount,
            CredentialAsJson = attestationObject.AuthenticatorData.CredentialPublicKeyAsJson
        });

        // TODO: recommended to store transports alongside key (call getTransports()) to use in future allowCredentials options

        new FidoRegistrationResult
        {
            IsSuccess = true,
            UserId = options.User.Id,
            Username = options.User.Name,
            CredentialId = attestationObject.AuthenticatorData.CredentialId
        };
    }
}

public class FidoRegistrationResult
{
    public bool IsSuccess { get; set; }
    public string ErrorMessage { get; set; }
    
    public byte[] UserId { get; set; }
    public string Username { get; set; }
    public byte[] CredentialId { get; set; }
}