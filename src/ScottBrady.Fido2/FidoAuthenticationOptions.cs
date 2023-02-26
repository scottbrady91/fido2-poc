namespace ScottBrady.Fido2.Models;

public class FidoAuthenticationOptions
{
    /// <summary>
    /// <para>The cryptographically random challenge used to match an authenticator response to a WebAuthn request.</para>
    /// <para>Must be at least 16-bytes long.</para>
    /// </summary>
    public byte[] Challenge { get; set; }
    
    public string Test { get; set; }
}