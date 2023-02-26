using System;
using System.Text.Json.Nodes;
using ScottBrady.Fido2.Models;

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