using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using ScottBrady.Fido2.Cryptography;

namespace ScottBrady.Fido2.Stores;

/// <summary>
/// JSON file implementation of <see cref="IFidoKeyStore"/>.
/// </summary>
public class JsonFidoKeyStore : IFidoKeyStore
{
    /// <summary>
    /// The keys from the JSON file loaded into memory.
    /// </summary>
    public IList<FidoKey> Keys { get; } = new List<FidoKey>();
    
    private static readonly JsonSerializerOptions Options = new JsonSerializerOptions
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
    private readonly string filePath;

    /// <summary>
    /// Creates a new JsonFidoKeyStore.
    /// Loads the JSON file's list of keys into memory.
    /// </summary>
    /// <param name="filePath">The file path. Must have read & write permissions.</param>
    public JsonFidoKeyStore(string filePath)
    {
        this.filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        if (!File.Exists(filePath)) File.WriteAllText(filePath, "[]");

        lock (Keys)
        {
            var json = File.ReadAllText(filePath);
            var jsonKeys = JsonSerializer.Deserialize<IList<JsonFidoKey>>(json, Options);
            Keys = jsonKeys.Select(x => x.ToFidoKey()).ToList();
        }
    }

    /// <inheritdoc />
    public Task<FidoKey> GetByUsername(string username)
    {
        if (username == null) throw new ArgumentNullException(nameof(username));

        lock (Keys)
        {
            // TODO: should IFidoKeySotre.GetByUsername return IEnumerable<FidoKey>???
            return Task.FromResult(Keys.FirstOrDefault(x => x.Username == username));
        }
    }

    /// <inheritdoc />
    public Task<FidoKey> GetByCredentialId(byte[] credentialId)
    {
        if (credentialId == null) throw new ArgumentNullException(nameof(credentialId));

        lock (Keys)
        {
            return Task.FromResult(Keys.FirstOrDefault(x => x.CredentialId == credentialId));
        }
    }

    /// <inheritdoc />
    public Task Store(FidoKey key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        
        lock (Keys)
        {
            key.Created = DateTime.UtcNow;
            key.LastUsed = DateTime.UtcNow;
            Keys.Add(key);
            
            var jsonKeys = Keys.Select(x => new JsonFidoKey(x)).ToList();
            File.WriteAllText(filePath, JsonSerializer.Serialize(jsonKeys, Options));
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task UpdateCounter(byte[] credentialId, int counter)
    {
        if (credentialId == null) throw new ArgumentNullException(nameof(credentialId));
        if (counter <= 0) throw new FidoException("Cannot update counter - must not be less than or equal to zero");
        
        lock (Keys)
        {
            var key = Keys.FirstOrDefault(x => x.CredentialId.SequenceEqual(credentialId));
            if (key == null) throw new FidoException("Could not update counter - unable to find key");
            
            key.Counter = counter;
            key.LastUsed = DateTime.UtcNow;
            
            var jsonKeys = Keys.Select(x => new JsonFidoKey(x)).ToList();
            File.WriteAllText(filePath, JsonSerializer.Serialize(jsonKeys, Options));
        }
        
        return Task.CompletedTask;
    }

    private class JsonFidoKey
    {
        [JsonConstructor]
        public JsonFidoKey() { }
        
        public JsonFidoKey(FidoKey key)
        {
            UserId = key.UserId;
            Username = key.Username;
            CredentialId = key.CredentialId;
            DeviceFriendlyName = key.DeviceFriendlyName;
            Counter = key.Counter;
            KeyAsJson = key.CredentialPublicKey.KeyAsJson;
            Created = key.Created;
            LastUsed = key.LastUsed;
        }
        
        public byte[] UserId { get; set; }
        public string Username { get; set; }
        public byte[] CredentialId { get; set; }
        public string DeviceFriendlyName { get; set; }
    
        public int Counter { get; set; }
        public string KeyAsJson { get; set; }

        public DateTime? Created { get; set; }
        public DateTime? LastUsed { get; set; }

        public FidoKey ToFidoKey()
        {
            return new FidoKey
            {
                UserId = UserId,
                Username = Username,
                CredentialId = CredentialId,
                DeviceFriendlyName = DeviceFriendlyName,
                Counter = Counter,
                CredentialPublicKey = new CredentialPublicKey(KeyAsJson),
                Created = Created,
                LastUsed = LastUsed
            };
        }
    } 
}