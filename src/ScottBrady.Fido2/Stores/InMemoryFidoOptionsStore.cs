using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using ScottBrady.Fido2.Models;

namespace ScottBrady.Fido2.Stores;

/// <summary>
/// In-memory implementation of <see cref="IFidoOptionsStore"/>.
/// </summary>
public class InMemoryFidoOptionsStore : IFidoOptionsStore
{
    /// <summary>
    /// The inner dictionary used for in-memory storage of PublicKeyCredentialCreationOptions.
    /// </summary>
    public static readonly ConcurrentDictionary<string, PublicKeyCredentialCreationOptions> RegistrationOptions = new ConcurrentDictionary<string, PublicKeyCredentialCreationOptions>();
    
    /// <summary>
    /// The inner dictionary used for in-memory storage of PublicKeyCredentialRequestOptions.
    /// </summary>
    public static readonly ConcurrentDictionary<string, PublicKeyCredentialRequestOptions> AuthenticationOptions = new ConcurrentDictionary<string, PublicKeyCredentialRequestOptions>();

    /// <inheritdoc />
    public Task Store(PublicKeyCredentialCreationOptions options)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        
        RegistrationOptions.AddOrUpdate(CreateKey(options.Challenge), options, (_, _) => options);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task Store(PublicKeyCredentialRequestOptions options)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        
        AuthenticationOptions.AddOrUpdate(CreateKey(options.Challenge), options, (_, _) => options);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<PublicKeyCredentialCreationOptions> TakeRegistrationOptions(byte[] challenge)
    {
        if (challenge == null) throw new ArgumentNullException(nameof(challenge));
        
        var key = CreateKey(challenge);
        RegistrationOptions.TryRemove(key, out var options);
        return Task.FromResult(options);
    }

    /// <inheritdoc />
    public Task<PublicKeyCredentialRequestOptions> TakeAuthenticationOptions(byte[] challenge)
    {
        if (challenge == null) throw new ArgumentNullException(nameof(challenge));
        
        var key = CreateKey(challenge);
        AuthenticationOptions.TryRemove(key, out var options);
        return Task.FromResult(options);
    }

    /// <summary>
    /// Helper method for converting challenge value into a dictionary key.
    /// </summary>
    public static string CreateKey(byte[] value) => Convert.ToBase64String(value);
}