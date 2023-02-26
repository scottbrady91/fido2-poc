using ScottBrady.Fido2.Parsers;

namespace ScottBrady.Fido2.Models;

/// <summary>
/// Parsed clientDataJSON from registration or authentication.
/// This is request-specific data used by the relying party (web server) and client (WebAuthn API).
/// </summary>
/// <remarks>
/// This library's implementation of the <a href="https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata">CollectedClientData</a> structure.
/// </remarks>
public class ClientData
{
    /// <summary>
    /// <para>The operation that was performed.</para>
    /// <para>Must be "webauthn.create" for registration and "webauthn.get" when authenticating.</para> 
    /// </summary>
    /// <example></example>
    public string Type { get; set; }
    
    /// <summary>
    /// <para>The cryptographically random challenge used to match an authenticator response to a WebAuthn request.</para>
    /// <para>Must be at least 16-bytes long.</para>
    /// </summary>
    public string Challenge { get; set; }
    
    /// <summary>
    /// The fully qualified origin of the requester that was password from the client (WebAuthn API) to the authenticator.
    /// </summary>
    /// <example>https://login.example.com:1337</example>
    public string Origin { get; set; }
    
    /// <summary>
    /// If WebAuthn was used in a cross-origin iframe. 
    /// </summary>
    public bool CrossOrigin { get; set; }

    /// <summary>
    /// The state of the Token Binding protocol used when communicating with the relying party. 
    /// Token Binding is largely unused, as is this property.
    /// </summary>
    public TokenBinding TokenBinding { get; set; }
}