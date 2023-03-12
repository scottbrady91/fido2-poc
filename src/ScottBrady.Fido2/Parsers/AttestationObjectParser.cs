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
        CBORObject cbor;
        using (var ms = new MemoryStream(attestationObject.ToArray()))
        {
            cbor = CBORObject.Read(ms);
            if (ms.Position != ms.Length) throw new FidoException("Invalid attestationObject length");
        }
        
        var attestationStatementFormat = cbor["fmt"];
        if (attestationStatementFormat.IsNull) throw new FidoException("Invalid attestationObject - missing fmt value");
        if (attestationStatementFormat.Type != CBORType.TextString) throw new FidoException("Invalid attestationObject - fmt must be a text string");
        
        var attestationStatement = cbor["attStmt"];
        if (attestationStatement.IsNull) throw new FidoException("Invalid attestationObject - missing attStmt value");
        if (attestationStatement.Type != CBORType.Map) throw new FidoException("Invalid attestationObject - attStmt must be a map");
        
        var authenticatorDataCbor = cbor["authData"];
        if (authenticatorDataCbor.IsNull) throw new FidoException("Invalid attestationObject - missing authData value");
        if (authenticatorDataCbor.Type != CBORType.ByteString) throw new FidoException("Invalid attestationObject - authData must be a byte string");
        
        var authenticatorData = authenticatorDataParser.Parse(authenticatorDataCbor.GetByteString());
        
        return new AttestationObject
        {
            StatementFormat = attestationStatementFormat.AsString(),
            Statement = attestationStatement.EncodeToBytes(),
            AuthenticatorData = authenticatorData
        };
    }
}