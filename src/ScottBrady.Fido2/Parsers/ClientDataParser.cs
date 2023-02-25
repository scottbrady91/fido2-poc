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
        
        // TODO: take copy clientDataJSON?
        return new ClientData
        {
            Type = type,
            Challenge = challenge,
            Origin = origin,
            CrossOrigin = crossOrigin ?? false
        };
    }
}

/// <summary>
/// Parsed clientDataJSON from registration or authentication.
/// Excludes optional TokenBinding member.
/// </summary>
public class ClientData
{
    public string Type { get; set; }
    public string Challenge { get; set; }
    public string Origin { get; set; }
    public bool CrossOrigin { get; set; }
}