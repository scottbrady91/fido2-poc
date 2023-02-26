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
    private readonly FidoOptions configurationOptions;
    private readonly IFidoKeyStore keyStore = new InMemoryFidoKeyStore();

    public FidoRegistrationService(IFidoOptionsStore optionsStore, FidoOptions configurationOptions)
    {
        this.optionsStore = optionsStore ?? throw new ArgumentNullException(nameof(optionsStore));
        this.configurationOptions = configurationOptions ?? throw new ArgumentNullException(nameof(configurationOptions));
    }
    
    public async Task<PublicKeyCredentialCreationOptions> Initiate(FidoRegistrationRequest request)
    {
        // TODO: global: relying party
        // TODO: overrides: timeout, algs (PublicKeyCredentialParameters), excludeCredentials?, authenticatorSelection???, attestation preference, extensions (pass though?)

        var options = new PublicKeyCredentialCreationOptions
        {
            User = new PublicKeyCredentialUserEntity
            {
                Id = RandomNumberGenerator.GetBytes(32),
                Name = request.Username,
                DisplayName = request.UserDisplayName
            },
            Challenge = RandomNumberGenerator.GetBytes(32),
            DeviceDisplayName = request.DeviceDisplayName
        };

        if (configurationOptions.RelyingPartyId is not null || configurationOptions.RelyingPartyName is not null)
        {
            options.Rp = new PublicKeyCredentialRpEntity
            {
                Id = configurationOptions.RelyingPartyId,
                Name = configurationOptions.RelyingPartyName
            };
        }
        
        await optionsStore.Store(options);

        return options;
    }
    
    public async Task<FidoRegistrationResult> Complete(PublicKeyCredential credential)
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
        var key = new FidoKey
        {
            UserId = options.User.Id,
            DeviceFriendlyName = options.DeviceDisplayName,
            CredentialId = attestationObject.AuthenticatorData.CredentialId,
            Counter = attestationObject.AuthenticatorData.SignCount,
            CredentialAsJson = attestationObject.AuthenticatorData.CredentialPublicKeyAsJson
        };
        await keyStore.Store(key);

        // TODO: recommended to store transports alongside key (call getTransports()) to use in future allowCredentials options


        return FidoRegistrationResult.Success(key, attestationObject);
    }
}