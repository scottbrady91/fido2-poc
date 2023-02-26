using System;
using System.IO;
using System.Linq;
using PeterO.Cbor;
using ScottBrady.Fido2.Models;

namespace ScottBrady.Fido2.Parsers;

public class AuthenticatorDataParser
{
    public AuthenticatorData Parse(ReadOnlySpan<byte> authenticatorData)
    {
        var parsedData = new AuthenticatorData();

        using var ms = new MemoryStream(authenticatorData.ToArray());
        
        parsedData.RpIdHash = ms.ReadBytes(32);

        var flags = (Flags)ms.ReadBytes(1)[0];
        parsedData.UserPresent = (flags & Flags.UserPresent) != 0;
        parsedData.UserVerified = (flags & Flags.UserVerified) != 0;
        parsedData.AttestedCredentialDataIncluded = (flags & Flags.AttestedCredentialDataIncluded) != 0;
        parsedData.ExtensionDataIncluded = (flags & Flags.ExtensionsDataIncluded) != 0;
            
        parsedData.SignCount = Convert.ToInt32(BitConverter.ToUInt32(ms.ReadBytes(4).Reverse().ToArray())); // TODO: wtf
            
        if (parsedData.AttestedCredentialDataIncluded)
        {
            parsedData.Aaguid = ms.ReadBytes(16);

            var credentialIdLength = BitConverter.ToUInt16(ms.ReadBytes(2).Reverse().ToArray());
            parsedData.CredentialId = ms.ReadBytes(credentialIdLength);
                
            parsedData.CredentialPublicKeyAsJson = CBORObject.Read(ms).ToJSONString();
        }

        if (parsedData.ExtensionDataIncluded)
        {
            parsedData.Extensions = CBORObject.Read(ms);
        }

        return parsedData;
    }
    
    [Flags]
    private enum Flags : byte
    {
        UserPresent = 1,
        UserVerified = 4,
        AttestedCredentialDataIncluded = 64,
        ExtensionsDataIncluded = 128
    }
}