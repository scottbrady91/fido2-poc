﻿using System.Text.Json;
using System.Text.Json.Serialization;

namespace ScottBrady.Fido2;

/// <summary>
/// Library configuration options.
/// </summary>
public class FidoOptions
{
    /// <summary>
    /// <para>Overrides the ID that uniquely identifies the relying party (web application).
    /// This is the <a href="https://www.w3.org/TR/webauthn-2/#rp-id">RP ID</a> used by the WebAuthn API.</para>
    /// <para>Must be a valid domain string and must be a registrable domain suffix of or is equal to the caller’s origin's effective domain
    /// (e.g. for an origin of https://login.example.com:1337, the RP ID is login.example.com or example.com).</para>
    /// If not provided, defaults to the origin's effective domain.
    /// </summary>
    /// <example>login.example.com</example>
    public string RelyingPartyId { get; set; }
    
    /// <summary>
    /// <para>A human-readable identifier for the relying party (web application), set by the relying party.</para>
    /// <para>This value can be displayed to the user and will be stored by the authenticator.</para>
    /// <para>May be truncated by the authenticator if over 64-bytes.</para>
    /// </summary>
    /// <example>ACME Corp</example>
    public string RelyingPartyName { get; set; }

    public JsonSerializerOptions JsonOptions { get; set; } = new JsonSerializerOptions
    {
        Converters = { new IntArrayJsonConverter(), new EmptyToNullStringConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
        PropertyNameCaseInsensitive = true
    }; // TODO: check handling style in Microsoft.IdentityModel
}