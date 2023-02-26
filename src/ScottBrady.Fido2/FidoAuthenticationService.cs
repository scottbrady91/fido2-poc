using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.Fido2.Cryptography;
using ScottBrady.Fido2.Models;
using ScottBrady.Fido2.Parsers;
using ScottBrady.Fido2.Stores;

namespace ScottBrady.Fido2;

// TODO: lookup by username?

public class FidoAuthenticationService
{
    private const string RpId = "localhost";
    private readonly IClientDataParser clientDataParser = new ClientDataParser();
    private readonly AuthenticatorDataParser authenticatorDataParser = new AuthenticatorDataParser();
    
    private readonly IFidoOptionsStore optionsStore;
    private readonly IFidoKeyStore keyStore;
    
    public FidoAuthenticationService(IFidoOptionsStore optionsStore, IFidoKeyStore keyStore)
    {
        this.optionsStore = optionsStore ?? throw new ArgumentNullException(nameof(optionsStore));
        this.keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
    }
    
    public async Task<PublicKeyCredentialRequestOptions> Initiate(FidoAuthenticationRequest request)
    {
        // TODO: set/override timeout
        // TODO: global RPID
        // TODO: set/override extensions?

        // TODO: lookup key by username :(
        
        // test code - for hardcoded user, single key in system
        var key = InMemoryFidoKeyStore.Keys.First();

        var options = new PublicKeyCredentialRequestOptions
        {
            Challenge = RandomNumberGenerator.GetBytes(32),
            RpId = RpId,
            AllowCredentials = new []{new PublicKeyCredentialDescriptor{Id = key.CredentialId, Type = "public-key"}},
            // TODO: make AllowCredentials optional??? Required when you know the user? Try again later...
            UserVerification = request.UserVerification ?? FidoConstants.UserVerificationRequirement.Preferred
        };
        
        await optionsStore.Store(options);

        return options;
    }

    // TODO: wrapper for options that includes custom data (e.g. expected user handle & device name during registration)
    public async Task Complete(PublicKeyCredential credential)
    {
        if (credential.Response is not AuthenticatorAssertionResponse response) throw new Exception("Incorrect response");
        var clientData = clientDataParser.Parse(response.ClientDataJson);
        
        // TODO: remove Microsoft.IdentityModel dependency
        var challenge = Base64UrlEncoder.DecodeBytes(clientData.Challenge);
        var options = await optionsStore.TakeAuthenticationOptions(challenge);
        if (options == null) throw new Exception("Incorrect options");
        
        // TODO: verify all allowed credentials
        if (options.AllowCredentials?.Any() == true)
        {
            //
        }
        
        var key = await keyStore.GetByCredentialId(Base64UrlEncoder.DecodeBytes(credential.Id));
        if (key == null) throw new Exception("Incorrect key");

        // TODO: also validate against user identified
        if (response.UserHandle != null && !response.UserHandle.SequenceEqual(key.UserId)) throw new Exception("Incorrect key for user");
        
        
        // TODO: verify user handle
        // known during auth: confirm owner of key
        // unknown during auth: confirm present and owner of key

        if (clientData.Type != "webauthn.get") throw new Exception("Incorrect type");
        if (!challenge.SequenceEqual(options.Challenge)) throw new Exception("Incorrect challenge");
        if (clientData.Origin != "https://localhost:5000") throw new Exception("Incorrect origin");
        if (clientData.TokenBinding != null && clientData.TokenBinding.Status == FidoConstants.TokenBindingStatus.Present) throw new Exception("Incorrect token binding");

        var authenticatorData = authenticatorDataParser.Parse(response.AuthenticatorData);
        if (!SHA256.HashData(Encoding.UTF8.GetBytes(RpId)).SequenceEqual(authenticatorData.RpIdHash)) throw new Exception("Incorrect RP ID");
        
        if (authenticatorData.UserPresent == false) throw new Exception("Incorrect user present");
        
        if (options.UserVerification == FidoConstants.UserVerificationRequirement.Required && !authenticatorData.UserVerified) throw new Exception("Incorrect UV");
        
        // TODO: hook to validate extensions?

        var hash = SHA256.HashData(response.ClientDataJson);
        var dataToValidate = new byte[response.AuthenticatorData.Length + hash.Length];
        response.AuthenticatorData.CopyTo(dataToValidate, 0);
        hash.CopyTo(dataToValidate, response.AuthenticatorData.Length);
        
        var signatureValidator = new FidoSignatureValidator();
        await signatureValidator.ValidateSignature(dataToValidate, response.Signature, key.CredentialAsJson);


        // TODO: validate & update signature counter
        
        
    }
}