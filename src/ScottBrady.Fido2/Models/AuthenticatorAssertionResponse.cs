namespace ScottBrady.Fido2.Models;

public class AuthenticatorAssertionResponse : AuthenticatorResponse
{
    public byte[] AuthenticatorData { get; set; }
    public byte[] Signature { get; set; }
    public byte[] UserHandle { get; set; }
}