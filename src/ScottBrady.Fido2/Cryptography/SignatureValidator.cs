using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ScottBrady.Fido2.Cryptography;

public class SignatureValidator
{
    private IEnumerable<ISignatureValidationStrategy> validators = new List<ISignatureValidationStrategy>();

    public Task ValidateSignature(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, string keyAsJson)
    {
        // parse key
        
        
        // validate signature


        throw new NotImplementedException();
    }
}

public interface ISignatureValidationStrategy
{
    Task ValidateSignature(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, string keyAsJson);
}