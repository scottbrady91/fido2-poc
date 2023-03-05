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
    public Task<IEnumerable<FidoKey>> GetByUsername(string username)
    {
        if (username == null) throw new ArgumentNullException(nameof(username));
        
        IEnumerable<FidoKey> keys;
        lock (Keys)
        {
            keys = Keys.Where(x => x.Username == username).ToList();
        }

        return Task.FromResult(keys);
    }
    
    /// <inheritdoc />
    public Task<FidoKey> GetByCredentialId(byte[] credentialId)
    {
        if (credentialId == null) throw new ArgumentNullException(nameof(credentialId));
        
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
        if (key == null) throw new ArgumentNullException(nameof(key));
        
        lock (Keys)
        {
            // TODO: system clock? (JSON store too)
            key.Created = DateTime.UtcNow;
            key.LastUsed = DateTime.UtcNow;

            Keys.Add(key);
        }
        
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task UpdateCounter(byte[] credentialId, uint counter)
    {
        if (credentialId == null) throw new ArgumentNullException(nameof(credentialId));
        if (counter <= 0) throw new FidoException("Cannot update counter - must not be less than or equal to zero");

        lock (Keys)
        {
            var key = Keys.FirstOrDefault(x => x.CredentialId.SequenceEqual(credentialId));
            if (key == null) throw new FidoException("Could not update counter - unable to find key");

            key.Counter = counter;
            key.LastUsed = DateTime.UtcNow;
        }

        return Task.CompletedTask;
    }
}