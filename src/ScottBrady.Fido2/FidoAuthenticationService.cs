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

/// <summary>
/// WebAuthn authentication service.
/// Follows standardized procedure to <a href="https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion">verify an authentication assertion</a>.
/// </summary>
public interface IFidoAuthenticationService
{
    /// <summary>
    /// Initiates authentication by generating and storing <see cref="PublicKeyCredentialRequestOptions"/>.
    /// </summary>
    /// <param name="request">
    /// Request-specific data for initiating authentication.
    /// Sets user information and allows user verification to be overridden for an individual request.
    /// </param>
    /// <returns>
    ///
    /// </returns>
    Task<PublicKeyCredentialRequestOptions> Initiate(FidoAuthenticationRequest request);
    
    /// <summary>
    /// Completes authentication by validating the <see cref="PublicKeyCredential"/> returned from the WebAuthn API against the original <see cref="PublicKeyCredentialRequestOptions"/>.
    /// </summary>
    /// <param name="credential">The credential returned from the WebAuthn API</param>
    /// <returns>The authentication result</returns>
    Task<FidoAuthenticationResult> Complete(PublicKeyCredential credential);
}

/// <inheritdoc />
public class FidoAuthenticationService : IFidoAuthenticationService
{
    private const string RpId = "localhost";
    private readonly IClientDataParser clientDataParser = new ClientDataParser();
    private readonly AuthenticatorDataParser authenticatorDataParser = new AuthenticatorDataParser();
    
    private readonly IFidoOptionsStore optionsStore;
    private readonly IFidoSignatureValidator signatureValidator;
    private readonly IFidoKeyStore keyStore;
    
    /// <summary>
    /// Creates a new <see cref="FidoAuthenticationService"/>.
    /// </summary>
    public FidoAuthenticationService(
        IFidoOptionsStore optionsStore,
        IFidoSignatureValidator signatureValidator,
        IFidoKeyStore keyStore)
    {
        this.optionsStore = optionsStore ?? throw new ArgumentNullException(nameof(optionsStore));
        this.signatureValidator = signatureValidator ?? throw new ArgumentNullException(nameof(signatureValidator));
        this.keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
    }
    
    // TODO: reg: user handle, credential ID

    /// <inheritdoc />
    public async Task<PublicKeyCredentialRequestOptions> Initiate(FidoAuthenticationRequest request)
    {
        // TODO: set/override timeout
        // TODO: global RPID
        // TODO: set/override extensions?
        
        var keys = await keyStore.GetByUsername(request.Username);
        if (keys == null) throw new FidoException("Unknown user"); // TODO: return enumeration resistant response?

        var options = new PublicKeyCredentialRequestOptions(RandomNumberGenerator.GetBytes(32))
        {
            RpId = RpId,
            // TODO: make AllowCredentials optional???
            UserVerification = request.UserVerification ?? WebAuthnConstants.UserVerificationRequirement.Preferred
        };

        options.AllowCredentials = keys.Select(x => new PublicKeyCredentialDescriptor(x.CredentialId)).ToList();
        
        await optionsStore.Store(options);

        return options;
    }

    // TODO: wrapper for options that includes custom data (e.g. expected user handle & device name during registration)
    /// <inheritdoc />
    public async Task<FidoAuthenticationResult> Complete(PublicKeyCredential credential)
    {
        if (credential.Response is not AuthenticatorAssertionResponse response) throw new Exception("Incorrect response");
        var clientData = clientDataParser.Parse(response.ClientDataJson);
        
        // TODO: remove Microsoft.IdentityModel dependency
        var challenge = Base64UrlEncoder.DecodeBytes(clientData.Challenge);
        var options = await optionsStore.TakeAuthenticationOptions(challenge);
        if (options == null) throw new Exception("Incorrect options");
        
        if (options.AllowCredentials?.Any() == true)
        {
            if (options.AllowCredentials.All(x => !x.Id.SequenceEqual(credential.RawId)))
                return FidoAuthenticationResult.Failure("Incorrect credential used - ID not present in requested credential list (allowCredentials)");
        }
        
        var key = await keyStore.GetByCredentialId(credential.RawId);
        if (key == null) throw new Exception("Incorrect key");

        // TODO: also validate against user identified
        if (response.UserHandle != null && !response.UserHandle.SequenceEqual(key.UserId)) throw new Exception("Incorrect key for user");
        
        // TODO: verify user handle
        // known during auth: confirm owner of key
        // unknown during auth: confirm present and owner of key

        if (clientData.Type != "webauthn.get") throw new Exception("Incorrect type");
        if (!challenge.SequenceEqual(options.Challenge)) throw new Exception("Incorrect challenge");
        if (clientData.Origin != "https://localhost:5000") throw new Exception("Incorrect origin");
        if (clientData.TokenBinding != null && clientData.TokenBinding.Status == WebAuthnConstants.TokenBindingStatus.Present) throw new Exception("Incorrect token binding");

        var authenticatorData = authenticatorDataParser.Parse(response.AuthenticatorData);
        if (!SHA256.HashData(Encoding.UTF8.GetBytes(RpId)).SequenceEqual(authenticatorData.RpIdHash)) throw new Exception("Incorrect RP ID");
        
        if (authenticatorData.UserPresent == false) throw new Exception("Incorrect user present");
        
        if (options.UserVerification == WebAuthnConstants.UserVerificationRequirement.Required && !authenticatorData.UserVerified) throw new Exception("Incorrect UV");
        
        // TODO: hook to validate extensions

        var isValidSignature = await signatureValidator.HasValidSignature(response, key.CredentialPublicKey);
        if (!isValidSignature) return FidoAuthenticationResult.Failure("Invalid signature");

        await keyStore.UpdateCounter(key.CredentialId, authenticatorData.SignCount);

        return FidoAuthenticationResult.Success(key, authenticatorData);
    }
}