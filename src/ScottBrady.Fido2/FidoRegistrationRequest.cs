namespace ScottBrady.Fido2.Models;

// https://github.com/fido-alliance/conformance-test-tools-resources/blob/master/docs/FIDO2/Server/Conformance-Test-API.md#serverpublickeycredentialcreationoptionsrequest
public class FidoRegistrationRequest
{
    public FidoRegistrationRequest(string username, string displayName)
    {
        Username = username;
        DisplayName = displayName;
    }
    
    public string Username { get; set; }
    public string DisplayName { get; set; }
    public AuthenticatorSelectionCriteria AuthenticatorSelectionCriteria { get; set; }
    public AttestationConveyancePreference Attestation { get; set; } = AttestationConveyancePreference.None;
}

// https://w3c.github.io/webauthn/#enum-attestation-convey
public enum AttestationConveyancePreference
{
    None,
    Indirect,
    Direct,
    Enterprise
};