using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ScottBrady.Fido2.Stores;

public interface IFidoKeyStore
{
    Task<FidoKey> GetByCredentialId(byte[] credentialId);
    Task Store(FidoKey key);
}

public class InMemoryFidoKeyStore : IFidoKeyStore
{
    public Dictionary<string, FidoKey> Keys = new Dictionary<string, FidoKey>();

    public Task<FidoKey> GetByCredentialId(byte[] credentialId)
    {
        return Task.FromResult(Keys[Convert.ToBase64String(credentialId)]);
    }

    public Task Store(FidoKey key)
    {
        Keys[Convert.ToBase64String(key.CredentialId)] = key;
        return Task.CompletedTask;
    }
    
    
}

public class FidoKey
{
    public byte[] UserId { get; set; }
    public byte[] CredentialId { get; set; }
    public string DeviceFriendlyName { get; set; }
    
    public int Counter { get; set; }
    public string CredentialAsJson { get; set; }

    public DateTime? Created { get; set; }
    public DateTime? LastUsed { get; set; }
}