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

/// <summary>
/// WebAuthn registration service.
/// Follows standardized procedure to <a href="https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential">verify registering a new credential</a>.
/// </summary>
public interface IFidoRegistrationService
{
    /// <summary>
    /// Initiates registration by generating and storing <see cref="PublicKeyCredentialCreationOptions"/>.
    /// </summary>
    /// <param name="request">
    /// Request-specific data for initiating registration.
    /// Sets user information and allows authenticator preferences to be overridden for an individual request.
    /// </param>
    /// <returns>
    /// The <see cref="PublicKeyCredentialCreationOptions"/> to be passed into the WebAuthn API.
    /// </returns>
    Task<PublicKeyCredentialCreationOptions> Initiate(FidoRegistrationRequest request);
    
    /// <summary>
    /// Completes registration by validating the <see cref="PublicKeyCredential"/> returned from the WebAuthn API against the original <see cref="PublicKeyCredentialCreationOptions"/>.
    /// </summary>
    /// <param name="credential">The credential returned from the WebAuthn API</param>
    /// <returns>The registration result</returns>
    Task<FidoRegistrationResult> Complete(PublicKeyCredential credential);
}

/// <inheritdoc />
public class FidoRegistrationService : IFidoRegistrationService
{
    private readonly IClientDataParser clientDataParser;
    private readonly IAttestationObjectParser attestationObjectParser;
    private readonly IAttestationStatementValidator attestationStatementValidator;
    private readonly IFidoOptionsStore optionsStore;
    private readonly IFidoKeyStore keyStore;
    private readonly FidoOptions configurationOptions;

    /// <summary>
    /// Creates a new <see cref="FidoRegistrationService"/>.
    /// </summary>
    public FidoRegistrationService(
        IClientDataParser clientDataParser,
        IAttestationObjectParser attestationObjectParser,
        IAttestationStatementValidator attestationStatementValidator,
        IFidoOptionsStore optionsStore,
        IFidoKeyStore keyStore,
        IOptions<FidoOptions> configurationOptions)
    {
        this.clientDataParser = clientDataParser ?? throw new ArgumentNullException(nameof(clientDataParser));
        this.attestationObjectParser = attestationObjectParser ?? throw new ArgumentNullException(nameof(attestationObjectParser));
        this.attestationStatementValidator = attestationStatementValidator ?? throw new ArgumentNullException(nameof(attestationStatementValidator));
        this.optionsStore = optionsStore ?? throw new ArgumentNullException(nameof(optionsStore));
        this.keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
        this.configurationOptions = configurationOptions?.Value ?? throw new ArgumentNullException(nameof(configurationOptions));
    }

    /// <inheritdoc />
    public async Task<PublicKeyCredentialCreationOptions> Initiate(FidoRegistrationRequest request)
    {
        // TODO: overrides: timeout, algs (PublicKeyCredentialParameters), excludeCredentials?, extensions (pass though?)
        
        var existingKeysForUser = await keyStore.GetByUsername(request.Username);
        var options = new PublicKeyCredentialCreationOptions(configurationOptions, request, existingKeysForUser.ToList());
        await optionsStore.Store(options);
        return options;
    }

    /// <inheritdoc />
    public async Task<FidoRegistrationResult> Complete(PublicKeyCredential credential)
    {
        if (credential.Type != WebAuthnConstants.PublicKeyCredentialType.PublicKey) throw new FidoException("Incorrect type - not of type public-key");
        if (credential.Response is not AuthenticatorAttestationResponse response) throw new FidoException("Incorrect response - not of type AuthenticatorAttestationResponse");
        var clientData = clientDataParser.Parse(response.ClientDataJson);

        // TODO: remove Microsoft.IdentityModel dependency
        var challenge = Base64UrlEncoder.DecodeBytes(clientData.Challenge);
        var options = await optionsStore.TakeRegistrationOptions(challenge);
        if (options == null) throw new FidoException("Unable to find stored options for request - unsolicited PublicKeyCredential");
        
        if (clientData.Type != "webauthn.create") throw new FidoException("Incorrect type - must be webauthn.create");
        if (!challenge.SequenceEqual(options.Challenge)) throw new FidoException("Incorrect challenge value - may be a response for a different request");
        if (clientData.Origin != configurationOptions.RelyingPartyOrigin) throw new FidoException($"Incorrect origin in clientDataJSON - unexpected value '{clientData.Origin}'");
        if (clientData.TokenBinding != null && clientData.TokenBinding.Status == WebAuthnConstants.TokenBindingStatus.Present) throw new FidoException("Unsupported token binding status"); 
        
        var attestationObject = attestationObjectParser.Parse(response.AttestationObject);
        if (!attestationStatementValidator.IsValid(attestationObject)) throw new FidoException("Failed attestation statement validation"); 
        
        // var clientDataHash = SHA256.HashData(clientDataJson); // used for attestation statement validation
        // TODO: hook for attestation validation? Above checks enforce "none", but this could be extracted.

        if (!SHA256.HashData(Encoding.UTF8.GetBytes(configurationOptions.RelyingPartyId)).SequenceEqual(attestationObject.AuthenticatorData.RpIdHash)) 
            throw new FidoException("Incorrect RP ID - RpIdHash in authenticatorData does not match configured relying party ID - may be a response for a different relying party");

        if (attestationObject.AuthenticatorData.UserPresent == false) 
            throw new FidoException("User not present - WebAuthn requires the user to prove their intent");
        
        if (options.AuthenticatorSelectionCriteria?.UserVerification == WebAuthnConstants.UserVerificationRequirement.Required && !attestationObject.AuthenticatorData.UserVerified)
            throw new FidoException("User verification required but user did not verify their identity with the authenticator");

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

/// <summary>
/// Validates <a href="https://www.w3.org/TR/webauthn-2/#attestation-statement">attestation statements</a> against <a href="https://www.w3.org/TR/webauthn-2/#attestation-statement-format">attestation format</a> rules.
/// 
/// </summary>
public interface IAttestationStatementValidator
{
    /// <summary>
    /// Validates the attestationObject's attestation statement.
    /// </summary>
    bool IsValid(AttestationObject attestationObject);
}

/// <summary>
/// Default attestation statement validator.
/// Only supports the <a href="https://www.w3.org/TR/webauthn-2/#sctn-none-attestation">none format</a>.
/// </summary>
public class DefaultAttestationStatementValidator : IAttestationStatementValidator
{
    /// <inheritdoc />
    public bool IsValid(AttestationObject attestationObject)
    {
        // TODO: remove test or support packed statement format.
        /*if (attestationObject.StatementFormat == "packed")
        {
            if (0 < attestationObject.Statement.Length) return true;
            throw new FidoException("Missing statement for packed format");
        };*/
        
        if (attestationObject.StatementFormat != "none") throw new FidoException("Incorrect statement format - only 'none' is supported");
        if (attestationObject.Statement.Length != 1) throw new FidoException("Incorrect statement count - 'none' format expects 0 statements");

        return true;
    }
}