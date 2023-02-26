using System;
using System.Threading.Tasks;

namespace ScottBrady.Fido2.Stores;

public interface IFidoKeyStore
{
    Task<FidoKey> GetByUsername(string username);
    Task<FidoKey> GetByCredentialId(byte[] credentialId);
    Task Store(FidoKey key);
    Task UpdateCounter(byte[] credentialId, int counter);
}

public class FidoKey
{
    public byte[] UserId { get; set; }
    public string Username { get; set; }
    public byte[] CredentialId { get; set; }
    public string DeviceFriendlyName { get; set; }
    
    public int Counter { get; set; }
    public string CredentialAsJson { get; set; }

    public DateTime? Created { get; set; }
    public DateTime? LastUsed { get; set; }
}