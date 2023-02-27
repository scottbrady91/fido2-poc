using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace ScottBrady.Fido2.Cryptography;

/// <summary>
/// FIDO signature validator.
/// </summary>
public interface IFidoSignatureValidator
{
    /// <summary>
    /// Validates a FIDO signature
    /// </summary>
    /// <param name="data">The parsed data to validate the signature against. This is a concatenation of the authenticator data and a SHA-256 hash of the client data.</param>
    /// <param name="signature">The signature generated during the authentication ceremony.</param>
    /// <param name="coseKeyAsJson">The stored public key in a JSON format, using COSE identifiers.</param>
    /// <returns></returns>
    Task ValidateSignature(byte[] data, byte[] signature, string coseKeyAsJson);
}

/// <inheritdoc />
public class FidoSignatureValidator : IFidoSignatureValidator
{
    private IEnumerable<ISignatureValidationStrategy> validators = new List<ISignatureValidationStrategy>();

    /// <inheritdoc />
    public Task ValidateSignature(byte[] data, byte[] signature, string coseKeyAsJson)
    {
        var jsonNode = JsonNode.Parse(coseKeyAsJson);
        var kty = jsonNode["1"]?.GetValue<int>();
        
        // TODO: parse key (deserialize and validate in validator? Or before? Should this be on load from the store?)
        
        // TODO: move signature concatenation here?

        // TODO: get correct strategy
        ISignatureValidationStrategy strategy = kty == 2 ? new EcdsaSignatureValidationStrategy() : new RsaSignatureValidationStrategy();
        
        // TODO: validate signature
        var isValid = strategy.ValidateSignature(data, signature, coseKeyAsJson);
        if (!isValid) throw new Exception("sig issue");

        return Task.CompletedTask;
    }
}