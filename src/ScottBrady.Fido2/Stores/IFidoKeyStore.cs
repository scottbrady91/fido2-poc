using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using ScottBrady.Fido2.Cryptography;

namespace ScottBrady.Fido2.Stores;

public interface IFidoKeyStore
{
    Task<IEnumerable<FidoKey>> GetByUsername(string username);
    Task<FidoKey> GetByCredentialId(byte[] credentialId);
    Task Store(FidoKey key);
    Task UpdateCounter(byte[] credentialId, uint counter);
}

public class FidoKey
{
    public byte[] UserId { get; set; }
    public string Username { get; set; }
    public byte[] CredentialId { get; set; }
    public string DeviceFriendlyName { get; set; }
    
    public uint Counter { get; set; }
    public CredentialPublicKey CredentialPublicKey { get; set; }

    public DateTime? Created { get; set; }
    public DateTime? LastUsed { get; set; }
}