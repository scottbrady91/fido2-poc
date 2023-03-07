using System;
using Microsoft.Extensions.DependencyInjection;
using ScottBrady.Fido2.Cryptography;
using ScottBrady.Fido2.Parsers;
using ScottBrady.Fido2.Stores;

namespace ScottBrady.Fido2;

/// <summary>
/// Extensions for registering FIDO dependencies.
/// </summary>
public static class ServiceCollectionExtensions
{
    // TODO: IFidoRegistration thingy for better registration API
    /// <summary>
    /// Registers the core dependencies for acting as a WebAuthn relying party.
    /// </summary>
    public static IServiceCollection AddWebAuthn(this IServiceCollection services, Action<FidoOptions> configureOptions)
    {
        services.Configure(configureOptions);

        services.AddScoped<IClientDataParser, ClientDataParser>();
        services.AddScoped<IAttestationObjectParser, AttestationObjectParser>();
        services.AddScoped<IAuthenticatorDataParser, AuthenticatorDataParser>();
        
        services.AddScoped<IFidoSignatureValidator, FidoSignatureValidator>();
        
        
        
        // TODO: replace in-memory options store
        services.AddScoped<IFidoOptionsStore, InMemoryFidoOptionsStore>();
        
        services.AddScoped<IFidoAuthenticationService, FidoAuthenticationService>();
        services.AddScoped<IFidoRegistrationService, FidoRegistrationService>();

        return services;
    }

    /// <summary>
    /// Registers an in-memory implementation of IFidoKeyStore.
    /// </summary>
    public static IServiceCollection AddInMemoryKeyStore(this IServiceCollection services)
    {
        services.AddScoped<IFidoKeyStore, InMemoryFidoKeyStore>();
        return services;
    }

    /// <summary>
    /// Registers a JSON file implementation of IFidoKeyStore.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="filePath">The file path. Must have read and write permissions.</param>
    public static IServiceCollection AddJsonFileKeyStore(this IServiceCollection services, string filePath = "keys.json")
    {
        if (string.IsNullOrEmpty(filePath)) throw new ArgumentNullException(nameof(filePath));

        services.AddSingleton(_ => new JsonFidoKeyStore(filePath));
        services.AddScoped<IFidoKeyStore>(s => s.GetRequiredService<JsonFidoKeyStore>());
        return services;
    }
}