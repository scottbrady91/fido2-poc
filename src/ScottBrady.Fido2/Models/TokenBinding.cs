namespace ScottBrady.Fido2.Models;

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