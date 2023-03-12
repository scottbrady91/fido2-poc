using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using ScottBrady.Fido2.Models;

namespace ScottBrady.Fido2;

/// <summary>
/// Request-specific data for initiating registration.
/// Sets user information and allows authenticator and attestation requirements to be overridden for an individual request.
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
    /// If not provided, this value will be set to the username.
    /// </param>
    public FidoRegistrationRequest(string username, string userDisplayName = null)
    {
        if (string.IsNullOrWhiteSpace(username)) throw new ArgumentNullException(nameof(username));

        Username = username;
        UserDisplayName = !string.IsNullOrWhiteSpace(userDisplayName) ? userDisplayName : username;
    }

    /// <inheritdoc cref="PublicKeyCredentialUserEntity.Name"/>
    [JsonPropertyName("username")]
    public string Username { get; }
    
    /// <inheritdoc cref="PublicKeyCredentialUserEntity.DisplayName"/>
    [JsonPropertyName("displayName")]
    public string UserDisplayName { get; }
    
    /// <summary>
    /// Optional custom field for a human-readable name for the authenticator.
    /// Allows the user to identify what authenticators they have registered at the relying party (web server).
    /// Can be set by the user during or after registration.
    /// </summary>
    [JsonPropertyName("deviceDisplayName")]
    public string DeviceDisplayName { get; set; }
    
    /// <inheritdoc cref="Models.AuthenticatorSelectionCriteria"/>
    [JsonPropertyName("authenticatorSelection")]
    public AuthenticatorSelectionCriteria AuthenticatorSelectionCriteria { get; set; }
    
    /// <inheritdoc cref="PublicKeyCredentialCreationOptions.Attestation"/>
    [JsonPropertyName("attestation")]
    public string AttestationConveyancePreference { get; set; } = WebAuthnConstants.AttestationConveyancePreference.None;
    
    // TODO: docs for extensions
    [JsonPropertyName("extensions")]
    public Dictionary<string, object> Extensions { get; set; }
}