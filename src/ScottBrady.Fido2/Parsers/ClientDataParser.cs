using System;
using System.Text.Json;
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

/// <inheritdoc />
public class ClientDataParser : IClientDataParser
{
    /// <inheritdoc />
    public ClientData Parse(ReadOnlySpan<byte> clientDataJson)
    {
        try
        {
            return JsonSerializer.Deserialize<ClientData>(clientDataJson);
        }
        catch (Exception e)
        {
            throw new FidoException("Unable to parse clientDataJSON bytes", e);
        }
    }
}