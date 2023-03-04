using System;
using ScottBrady.Fido2.Models;

namespace ScottBrady.Fido2;

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
        if (string.IsNullOrWhiteSpace(username)) throw new ArgumentNullException(nameof(username));
        Username = username;
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
    public string UserVerification { get; set; } = WebAuthnConstants.UserVerificationRequirement.Preferred;
}