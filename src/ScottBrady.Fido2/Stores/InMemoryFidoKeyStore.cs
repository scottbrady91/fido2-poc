using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ScottBrady.Fido2.Stores;

/// <summary>
/// In-memory implementation of <see cref="IFidoKeyStore"/>.
/// </summary>
public class InMemoryFidoKeyStore : IFidoKeyStore
{
    /// <summary>
    /// The inner in-memory collection of keys.
    /// </summary>
    public static readonly IList<FidoKey> Keys = new List<FidoKey>();

    /// <inheritdoc />
    public Task<FidoKey> GetByCredentialId(byte[] credentialId)
    {
        FidoKey key;
        lock (Keys)
        {
            key = Keys.FirstOrDefault(x => x.CredentialId.SequenceEqual(credentialId));
        }

        return Task.FromResult(key);
    }

    /// <inheritdoc />
    public Task Store(FidoKey key)
    {
        lock (Keys)
        {
            // TODO: check if key already in use? Does that belong in "Store"?

            // TODO: system clock?
            key.Created = DateTime.UtcNow;
            key.LastUsed = DateTime.UtcNow;;

            Keys.Add(key);
        }
        
        return Task.CompletedTask;
    }
}