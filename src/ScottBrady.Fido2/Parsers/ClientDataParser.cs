using System;
using System.Text.Json.Nodes;
using ScottBrady.Fido2.Models;

namespace ScottBrady.Fido2.Parsers;

/// <summary>
/// Parses client data from clientDataJSON.
/// </summary>
public interface IClientDataParser
{
    /// <summary>
    /// Parses client data from clientDataJSON.
    /// </summary>
    /// <param name="clientDataJson">clientDataJSON as original bytes.</param>
    ClientData Parse(ReadOnlySpan<byte> clientDataJson);
}

/// <inheritdoc cref="IClientDataParser"/>
public class ClientDataParser : IClientDataParser
{
    /// <inheritdoc cref="IClientDataParser.Parse"/>
    /// <exception cref="FidoException">Unable to parse or find required values.</exception>
    public ClientData Parse(ReadOnlySpan<byte> clientDataJson)
    {
        var parsedObject = JsonNode.Parse(clientDataJson)?.AsObject() ?? throw new FidoException("Unable to parse clientDataJSON");
        
        var type = parsedObject["type"]?.GetValue<string>() ?? throw new FidoException("Client data missing required type value");
        var challenge = parsedObject["challenge"]?.GetValue<string>() ?? throw new FidoException("Client data missing required challenge value");
        var origin = parsedObject["origin"]?.GetValue<string>()  ?? throw new FidoException("Client data missing required origin value");
        var crossOrigin = parsedObject["crossOrigin"]?.GetValue<bool>();
        var tokenBinding = parsedObject["tokenBinding"]?.GetValue<TokenBinding>();
        
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