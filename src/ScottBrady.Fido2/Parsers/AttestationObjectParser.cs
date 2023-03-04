using System;
using System.IO;
using PeterO.Cbor;
using ScottBrady.Fido2.Models;

namespace ScottBrady.Fido2.Parsers;

public class AttestationObjectParser
{
    private readonly AuthenticatorDataParser authenticatorDataParser;

    public AttestationObjectParser(AuthenticatorDataParser authenticatorDataParser)
    {
        this.authenticatorDataParser = authenticatorDataParser ?? throw new ArgumentNullException(nameof(authenticatorDataParser));
    }
    
    public AttestationObject Parse(ReadOnlySpan<byte> attestationObject)
    {
        // TODO: guards (inc. length checks, CBOR error)

        CBORObject cbor;
        using (var ms = new MemoryStream(attestationObject.ToArray()))
        {
            cbor = CBORObject.Read(ms);
            if (ms.Position != ms.Length) throw new Exception();
        }
        
        var attestationStatementFormat = cbor["fmt"]; // should be textstring
        var attestationStatement = cbor["attStmt"]; // should be map
        var authenticatorDataCbor = cbor["authData"]; // should be bytes
        
        var authenticatorData = authenticatorDataParser.Parse(authenticatorDataCbor.GetByteString());
        
        return new AttestationObject
        {
            StatementFormat = attestationStatementFormat.AsString(),
            Statement = attestationStatement,
            AuthenticatorData = authenticatorData
        };
    }
}