using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.Fido2.Models;
using ScottBrady.Fido2.Parsers;
using ScottBrady.Fido2.Stores;

namespace ScottBrady.Fido2;

// https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
public class FidoRegistrationService
{
    private const string RpOrigin = "https://localhost:5000";

    private readonly ClientDataParser clientDataParser;
    private readonly AttestationObjectParser attestationObjectParser;
    private readonly IFidoOptionsStore optionsStore;
    private readonly IFidoKeyStore keyStore;
    private readonly FidoOptions configurationOptions;

    public FidoRegistrationService(
        ClientDataParser clientDataParser,
        AttestationObjectParser attestationObjectParser,
        IFidoOptionsStore optionsStore,
        IFidoKeyStore keyStore,
        IOptions<FidoOptions> configurationOptions)
    {
        this.clientDataParser = clientDataParser ?? throw new ArgumentNullException(nameof(clientDataParser));
        this.attestationObjectParser = attestationObjectParser ?? throw new ArgumentNullException(nameof(attestationObjectParser));
        this.optionsStore = optionsStore ?? throw new ArgumentNullException(nameof(optionsStore));
        this.keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
        this.configurationOptions = configurationOptions?.Value ?? throw new ArgumentNullException(nameof(configurationOptions));
    }
    
    public async Task<PublicKeyCredentialCreationOptions> Initiate(FidoRegistrationRequest request)
    {
        // TODO: overrides: timeout, algs (PublicKeyCredentialParameters), excludeCredentials?, extensions (pass though?)

        var options = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity(configurationOptions.RelyingPartyName) { Id = configurationOptions.RelyingPartyId },
            request)
        {
            PublicKeyCredentialParameters = new[]
            {
                new PublicKeyCredentialParameters { Type = "public-key", Algorithm = -7 },
                new PublicKeyCredentialParameters { Type = "public-key", Algorithm = -257 }
            }
            // Timeout =
            // Extensions = 
        };

        await optionsStore.Store(options);

        return options;
    }
    
    public async Task<FidoRegistrationResult> Complete(PublicKeyCredential credential)
    {
        if (credential.Response is not AuthenticatorAttestationResponse response) throw new FidoException("Incorrect response - not of type AuthenticatorAttestationResponse");
        var clientData = clientDataParser.Parse(response.ClientDataJson);

        // TODO: remove Microsoft.IdentityModel dependency
        var challenge = Base64UrlEncoder.DecodeBytes(clientData.Challenge);
        var options = await optionsStore.TakeRegistrationOptions(challenge);
        if (options == null) throw new FidoException("Unable to find stored options for request - unsolicited PublicKeyCredential");
        
        if (clientData.Type != "webauthn.create") throw new FidoException("Incorrect type - must be webauthn.create");
        if (!challenge.SequenceEqual(options.Challenge)) throw new FidoException("Incorrect challenge value - may be a response for a different request");
        if (clientData.Origin != RpOrigin) throw new FidoException($"Incorrect origin in clientDataJSON - unexpected value '{clientData.Origin}'");
        if (clientData.TokenBinding != null && clientData.TokenBinding.Status == WebAuthnConstants.TokenBindingStatus.Present) throw new FidoException("Unsupported token binding status"); 
        
        var attestationObject = attestationObjectParser.Parse(response.AttestationObject);
        if (attestationObject.StatementFormat != "none") throw new FidoException("Incorrect statement format - only 'none' is supported");
        if (attestationObject.Statement.Count != 0) throw new FidoException("Incorrect statement count - 'none' format expects 0 statements");
        
        // var clientDataHash = SHA256.HashData(clientDataJson); // used for attestation statement validation
        // TODO: hook for attestation validation? Above checks enforce "none", but this could be extracted.

        if (!SHA256.HashData(Encoding.UTF8.GetBytes(configurationOptions.RelyingPartyId)).SequenceEqual(attestationObject.AuthenticatorData.RpIdHash)) 
            throw new FidoException("Incorrect RP ID - RpIdHash in authenticatorData does not match configured relying party ID - may be a response for a different relying party");

        if (attestationObject.AuthenticatorData.UserPresent == false) 
            throw new FidoException("User not present - WebAuthn requires the user to prove their intent");
        
        if (options.AuthenticatorSelectionCriteria?.UserVerification == WebAuthnConstants.UserVerificationRequirement.Required && !attestationObject.AuthenticatorData.UserVerified)
            throw new FidoException("User verification required but user did not verify their identity with the authenticator");

        // TODO: check if alg was requested
        if (options.PublicKeyCredentialParameters.All(x => x.Algorithm.ToString() != attestationObject.AuthenticatorData.CredentialPublicKey.Algorithm))
            throw new FidoException($"Unsupported algorithm of '{attestationObject.AuthenticatorData.CredentialPublicKey.Algorithm}'");
        
        // TODO: hook to validate extensions?
        
        // validate credential ID is not registered to a different user (either fail or remove old registration)
        var existingCredential = await keyStore.GetByCredentialId(attestationObject.AuthenticatorData.CredentialId);
        if (existingCredential != null) throw new FidoException($"Credential ID '{Convert.ToBase64String(attestationObject.AuthenticatorData.CredentialId)}' already in use");

        // TODO: hook for custom validation (after core validate, before storage)

        // store key
        var key = new FidoKey
        {
            UserId = options.User.Id,
            Username = options.User.Name,
            DeviceFriendlyName = options.DeviceDisplayName,
            CredentialId = attestationObject.AuthenticatorData.CredentialId,
            Counter = attestationObject.AuthenticatorData.SignCount,
            CredentialPublicKey = attestationObject.AuthenticatorData.CredentialPublicKey
        };
        await keyStore.Store(key);

        // TODO: recommended to store transports alongside key (call getTransports()) to use in future allowCredentials options
        
        return FidoRegistrationResult.Success(key, attestationObject);
    }
}