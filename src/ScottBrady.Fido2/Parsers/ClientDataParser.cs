using System;
using System.Text.Json.Nodes;

namespace ScottBrady.Fido2.Parsers;

// TODO: documentation
public class ClientDataParser
{
    public ClientData Parse(ReadOnlySpan<byte> clientDataJson)
    {
        // TODO: argument checking
        var parsedObject = JsonNode.Parse(clientDataJson)?.AsObject() ?? throw new ArgumentException();
        
        var type = parsedObject["type"]?.GetValue<string>();
        var challenge = parsedObject["challenge"]?.GetValue<string>();
        var origin = parsedObject["origin"]?.GetValue<string>();
        var crossOrigin = parsedObject["crossOrigin"]?.GetValue<bool>();
        var tokenBinding = parsedObject["tokenBinding"]?.GetValue<TokenBinding>();
        
        // TODO: take copy clientDataJSON?
        // TODO: test enum parsing and ensure unknown values are rejected :(
        return new ClientData
        {
            Type = type,
            Challenge = challenge,
            Origin = origin,
            CrossOrigin = crossOrigin ?? false,
            TokenBinding = tokenBinding
        };
    }
}

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

/// <summary>
/// The state of the Token Binding protocol used when communicating with the relying party.
/// </summary>
public class TokenBinding
{
    /// <summary>
    /// The state of Token Binding for this request.
    /// Unknown values must be ignored.
    /// </summary>
    public TokenBindingStatus Status { get; set; }
    
    /// <summary>
    /// The base64url encoded Token Binding ID for this request.
    /// </summary>
    public string Id { get; set; }
    
    /// <summary>
    /// Token Binding states.
    /// </summary>
    public enum TokenBindingStatus
    {
        /// <summary>
        /// Token Binding is supported but was not used.
        /// </summary>
        Supported,
        
        /// <summary>
        /// Token Binding was used.
        /// </summary>
        Present
    }
}