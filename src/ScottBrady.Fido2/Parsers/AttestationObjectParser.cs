using System;
using System.IO;
using PeterO.Cbor;
using ScottBrady.Fido2.Models;

namespace ScottBrady.Fido2.Parsers;

/// <summary>
/// Parses an attestation object from attestationObject bytes.
/// </summary>
public interface IAttestationObjectParser
{
    /// <summary>
    /// Parses an attestation object from attestationObject bytes.
    /// </summary>
    /// <param name="attestationObject">attestationObject as original bytes.</param>
    AttestationObject Parse(ReadOnlySpan<byte> attestationObject);
}

/// <inheritdoc />
public class AttestationObjectParser : IAttestationObjectParser
{
    private readonly IAuthenticatorDataParser authenticatorDataParser;

    /// <summary>
    /// Creates a new AttestationObjectParser.
    /// </summary>
    public AttestationObjectParser(IAuthenticatorDataParser authenticatorDataParser)
    {
        this.authenticatorDataParser = authenticatorDataParser ?? throw new ArgumentNullException(nameof(authenticatorDataParser));
    }

    /// <inheritdoc />
    public AttestationObject Parse(ReadOnlySpan<byte> attestationObject)
    {
        // TODO: guards (inc. length checks, CBOR error)

        CBORObject cbor;
        using (var ms = new MemoryStream(attestationObject.ToArray()))
        {
            cbor = CBORObject.Read(ms);
            if (ms.Position != ms.Length) throw new FidoException("Invalid attestationObject length");
        }
        
        var attestationStatementFormat = cbor["fmt"]; // should be textstring
        var attestationStatement = cbor["attStmt"]; // should be map
        var authenticatorDataCbor = cbor["authData"]; // should be bytes
        
        var authenticatorData = authenticatorDataParser.Parse(authenticatorDataCbor.GetByteString());
        
        return new AttestationObject
        {
            StatementFormat = attestationStatementFormat.AsString(),
            Statement = attestationStatement.EncodeToBytes(),
            AuthenticatorData = authenticatorData
        };
    }
}