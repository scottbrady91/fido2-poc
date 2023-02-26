using System;
using ScottBrady.Fido2.Models;

namespace ScottBrady.Fido2;

/// <summary>
/// Request-specific data for initiating registration.
/// Sets user information and allows authenticator & attestation requirements to be overridden for an individual request.
/// </summary>
/// <remarks>
/// Matches requirements for <a href="https://github.com/fido-alliance/conformance-test-tools-resources/blob/master/docs/FIDO2/Server/Conformance-Test-API.md#serverpublickeycredentialcreationoptionsrequest">
/// ServerPublicKeyCredentialCreationOptionsRequest</a>.
/// </remarks>
public class FidoRegistrationRequest
{
    /// <summary>
    /// Creates a new registration request with required user data.
    /// </summary>
    /// <param name="username">
    /// The user's username.
    /// This value can be displayed to the user and will be stored by the authenticator.
    /// </param>
    /// <param name="userDisplayName">
    /// The user's display name.
    /// Used to differentiate between user accounts with similar display names.
    /// This value can be displayed to the user and will be stored by the authenticator.
    /// </param>
    public FidoRegistrationRequest(string username, string userDisplayName)
    {
        Username = username ?? throw new ArgumentNullException(nameof(username));
        UserDisplayName = userDisplayName ?? throw new ArgumentNullException(nameof(userDisplayName));
    }

    /// <inheritdoc cref="PublicKeyCredentialUserEntity.Name"/>
    public string Username { get; }
    
    /// <inheritdoc cref="PublicKeyCredentialUserEntity.DisplayName"/>
    public string UserDisplayName { get; }
    
    /// <summary>
    /// Optional custom field for a human-readable name for the authenticator.
    /// Allows the user to identify what authenticators they have registered at the relying party (web server).
    /// Can be set by the user during or after registration.
    /// </summary>
    public string DeviceDisplayName { get; set; }
    
    /// <inheritdoc cref="Models.AuthenticatorSelectionCriteria"/>
    public AuthenticatorSelectionCriteria AuthenticatorSelectionCriteria { get; set; }
    
    /// <inheritdoc cref="PublicKeyCredentialCreationOptions.AttestationConveyancePreference"/>
    public string AttestationConveyancePreference { get; set; } = FidoConstants.AttestationConveyancePreference.None;
}