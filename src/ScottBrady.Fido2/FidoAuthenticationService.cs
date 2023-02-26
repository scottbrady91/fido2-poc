﻿using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.Fido2.Models;
using ScottBrady.Fido2.Parsers;
using ScottBrady.Fido2.Stores;

namespace ScottBrady.Fido2;

// TODO: lookup by username?

public class FidoAuthenticationService
{
    private const string RpId = "localhost";
    private readonly ClientDataParser clientDataParser = new ClientDataParser();
    private readonly AuthenticatorDataParser authenticatorDataParser = new AuthenticatorDataParser();
    
    private readonly IFidoOptionsStore optionsStore;
    private readonly IFidoKeyStore keyStore = new InMemoryFidoKeyStore();
    
    public FidoAuthenticationService(IFidoOptionsStore optionsStore)
    {
        this.optionsStore = optionsStore ?? throw new ArgumentNullException(nameof(optionsStore));
    }
    
    public async Task<PublicKeyCredentialRequestOptions> Initiate(FidoAuthenticationRequest request)
    {
        // TODO: set/override timeout
        // TODO: global RPID
        // TODO: set/override extensions?

        var options = new PublicKeyCredentialRequestOptions
        {
            Challenge = RandomNumberGenerator.GetBytes(16),
            RpId = RpId,
            // TODO: AllowCredentials =
            // TODO: make AllowCredentials optional???
            UserVerification = request.UserVerification ?? FidoConstants.UserVerificationRequirement.Preferred
        };
        
        await optionsStore.Store(options);

        return options;
    }

    // TODO: what about Id & RawId & type? This is only accepting the response
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
        if (options.AllowCredentials.Any())
        {
            //
        }
        
        var key = await keyStore.GetByCredentialId(Base64UrlEncoder.DecodeBytes(credential.Id));
        if (key == null) throw new Exception("Incorrect key");
        
        // TODO: verify user handle
        // known during auth: confirm owner of key
        // unknown during auth: confirm present and owner of key

        
        
        
    }
}

/// <summary>
/// Request-specific data for initiating authentication.
/// Sets user information and allows user verification to be overridden for an individual request.
/// </summary>
/// <remarks>
/// Matches requirements for <a href="https://github.com/fido-alliance/conformance-test-tools-resources/blob/master/docs/FIDO2/Server/Conformance-Test-API.md#serverpublickeycredentialgetoptionsrequest">
/// ServerPublicKeyCredentialGetOptionsRequest</a>.
/// </remarks>
public class FidoAuthenticationRequest
{
    /// <summary>
    /// Creates a new authentication request with required user data.
    /// </summary>
    /// <param name="username">
    /// The user's username.
    /// This value can be displayed to the user and will be stored by the authenticator.
    /// </param>
    public FidoAuthenticationRequest(string username)
    {
        Username = username ?? throw new ArgumentNullException(nameof(username));
    }
    
    /// <inheritdoc cref="PublicKeyCredentialUserEntity.Name"/>
    public string Username { get; set; }

    /// <summary>
    /// <para>The relying party's requirement for user verification (e.g. a local PIN or biometric to use the authenticator).
    /// Should be a <a href="https://www.w3.org/TR/webauthn-2/#enumdef-userverificationrequirement">User Verification Requirement</a>, but open to future extensibility.</para>
    /// <para>Unknown values will be ignored by the client.</para>
    /// <para>Defaults to "preferred"</para>
    /// </summary>
    /// <example>preferred</example>
    public string UserVerification { get; set; } = FidoConstants.UserVerificationRequirement.Preferred;
}