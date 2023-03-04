using System.Text.Json.Serialization;

namespace ScottBrady.Fido2.Models;

// TODO: cleanup PublicKeyCredential & AuthenticatorResponse

// https://www.w3.org/TR/webauthn-2/#iface-pkcredential
public class PublicKeyCredential
{
    public string Id { get; set; }
    public byte[] RawId { get; set; }
    public string Type { get; set; }
    public AuthenticatorResponse Response { get; set; }
}

[JsonConverter(typeof(AuthenticatorResponseJsonConverter))]
public class AuthenticatorResponse
{
    public byte[] ClientDataJson { get; set; }
}


public class AuthenticatorAttestationResponse : AuthenticatorResponse
{
    public byte[] AttestationObject { get; set; }
}