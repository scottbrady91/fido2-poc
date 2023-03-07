using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
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
    /// The <see cref="PublicKeyCredentialRequestOptions"/> to be passed into the WebAuthn API.
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
    private readonly IClientDataParser clientDataParser;
    private readonly IAuthenticatorDataParser authenticatorDataParser;
    private readonly IFidoSignatureValidator signatureValidator;
    private readonly IFidoOptionsStore optionsStore;
    private readonly IFidoKeyStore keyStore;
    private readonly FidoOptions configurationOptions;
    
    /// <summary>
    /// Creates a new <see cref="FidoAuthenticationService"/>.
    /// </summary>
    public FidoAuthenticationService(
        IClientDataParser clientDataParser,
        IAuthenticatorDataParser authenticatorDataParser,
        IFidoSignatureValidator signatureValidator,
        IFidoOptionsStore optionsStore,
        IFidoKeyStore keyStore,
        IOptions<FidoOptions> configurationOptions)
    {
        this.clientDataParser = clientDataParser ?? throw new ArgumentNullException(nameof(clientDataParser));
        this.authenticatorDataParser = authenticatorDataParser ?? throw new ArgumentNullException(nameof(authenticatorDataParser));
        this.signatureValidator = signatureValidator ?? throw new ArgumentNullException(nameof(signatureValidator));
        this.optionsStore = optionsStore ?? throw new ArgumentNullException(nameof(optionsStore));
        this.keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
        this.configurationOptions = configurationOptions?.Value ?? throw new ArgumentNullException(nameof(configurationOptions));
    }
    
    // TODO: wrapper for options that includes custom data (e.g. expected user handle & device name during authentication)?
    /// <inheritdoc />
    public async Task<PublicKeyCredentialRequestOptions> Initiate(FidoAuthenticationRequest request)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        var keys = (await keyStore.GetByUsername(request.Username)).ToList();
        if (keys == null || !keys.Any()) throw new FidoException("Unknown user"); // TODO (passwordless): return enumeration resistant options & response

        var options = new PublicKeyCredentialRequestOptions(RandomNumberGenerator.GetBytes(32))
        {
            RpId = configurationOptions.RelyingPartyId,
            AllowCredentials = keys.Select(x => new PublicKeyCredentialDescriptor(x.CredentialId)).ToList(),
            UserVerification = request.UserVerification ?? WebAuthnConstants.UserVerificationRequirement.Preferred,
            // extensions
        };

        await optionsStore.Store(options);

        return options;
    }
    
    /// <inheritdoc />
    public async Task<FidoAuthenticationResult> Complete(PublicKeyCredential credential)
    {
        if (credential.Response is not AuthenticatorAssertionResponse response) throw new FidoException("Incorrect response - not of type AuthenticatorAssertionResponse");
        var clientData = clientDataParser.Parse(response.ClientDataJson);
        
        // TODO: remove Microsoft.IdentityModel dependency
        var challenge = Base64UrlEncoder.DecodeBytes(clientData.Challenge);
        var options = await optionsStore.TakeAuthenticationOptions(challenge);
        if (options == null) throw new FidoException("Unable to find stored options for request - unsolicited PublicKeyCredential");

        // TODO (usernameless): make allowCredentials optional
        if (options.AllowCredentials.All(x => !x.Id.SequenceEqual(credential.RawId)))
            throw new FidoException("Incorrect credential used - ID not present in requested credential list (allowCredentials)");
        
        var key = await keyStore.GetByCredentialId(credential.RawId);
        if (key == null) throw new FidoException("Unknown key - there is no key stored with this credential ID");

        // user handle only necessary when doing username-less
        // TODO (usernameless): enforce presence of user handle
        if (response.UserHandle != null 
            && response.UserHandle.Length != 0 
            && !response.UserHandle.SequenceEqual(key.UserId))
            throw new FidoException("Used key does not belong to this user (mismatch in user handle)");
        
        if (clientData.Type != "webauthn.get") throw new FidoException("Incorrect type - must be webauthn.create");
        if (!challenge.SequenceEqual(options.Challenge)) throw new FidoException("Incorrect challenge value - may be a response for a different request");
        if (clientData.Origin != configurationOptions.RelyingPartyOrigin) throw new FidoException($"Incorrect origin in clientDataJSON - unexpected value '{clientData.Origin}'");
        if (clientData.TokenBinding != null && clientData.TokenBinding.Status == WebAuthnConstants.TokenBindingStatus.Present) throw new FidoException("Unsupported token binding status");

        var authenticatorData = authenticatorDataParser.Parse(response.AuthenticatorData);
        if (!SHA256.HashData(Encoding.UTF8.GetBytes(configurationOptions.RelyingPartyId)).SequenceEqual(authenticatorData.RpIdHash)) 
            throw new FidoException("Incorrect RP ID - RpIdHash in authenticatorData does not match configured relying party ID - may be a response for a different relying party");
        
        if (authenticatorData.UserPresent == false) 
            throw new FidoException("User not present - WebAuthn requires the user to prove their intent");
        
        if (options.UserVerification == WebAuthnConstants.UserVerificationRequirement.Required && !authenticatorData.UserVerified)
            throw new FidoException("User verification required but user did not verify their identity with the authenticator");
        
        // TODO: hook to validate extensions

        var isValidSignature = await signatureValidator.HasValidSignature(response, key.CredentialPublicKey);
        if (!isValidSignature) throw new FidoException("Invalid signature");

        if (authenticatorData.SignCount <= key.Counter) throw new FidoException("SignCount is less than or equal to stored counter for key - authenticator may have been cloned");
        await keyStore.UpdateCounter(key.CredentialId, authenticatorData.SignCount);

        return FidoAuthenticationResult.Success(key, authenticatorData);
    }
}