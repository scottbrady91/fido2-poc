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
    /// The inner dictionary used for in-memory storage of FidoRegistrationOptions.
    /// </summary>
    public static readonly ConcurrentDictionary<string, FidoRegistrationOptions> RegistrationOptions = new ConcurrentDictionary<string, FidoRegistrationOptions>();
    
    /// <summary>
    /// The inner dictionary used for in-memory storage of FidoAuthenticationOptions.
    /// </summary>
    public static readonly ConcurrentDictionary<string, FidoAuthenticationOptions> AuthenticationOptions = new ConcurrentDictionary<string, FidoAuthenticationOptions>();

    /// <inheritdoc />
    public Task Store(FidoRegistrationOptions options)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        
        RegistrationOptions.AddOrUpdate(CreateKey(options.Challenge), options, (_, _) => options);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task Store(FidoAuthenticationOptions options)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        
        AuthenticationOptions.AddOrUpdate(CreateKey(options.Challenge), options, (_, _) => options);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<FidoRegistrationOptions> TakeRegistrationOptions(byte[] challenge)
    {
        if (challenge == null) throw new ArgumentNullException(nameof(challenge));
        
        var key = CreateKey(challenge);
        RegistrationOptions.TryRemove(key, out var options);
        return Task.FromResult(options);
    }

    /// <inheritdoc />
    public Task<FidoAuthenticationOptions> TakeAuthenticationOptions(byte[] challenge)
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