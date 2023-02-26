using System;
using System.Threading.Tasks;

namespace ScottBrady.Fido2.Stores;

public interface IFidoKeyStore
{
    Task<FidoKey> GetByCredentialId(byte[] credentialId);
    Task Store(FidoKey key);
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