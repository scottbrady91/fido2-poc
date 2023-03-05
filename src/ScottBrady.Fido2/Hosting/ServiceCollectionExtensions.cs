﻿using System;
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

        services.AddScoped<ClientDataParser>();
        services.AddScoped<AttestationObjectParser>();
        services.AddScoped<AuthenticatorDataParser>();
        
        services.AddScoped<IFidoSignatureValidator, FidoSignatureValidator>();
        
        
        
        // TODO: replace in-memory options store
        services.AddScoped<IFidoOptionsStore, InMemoryFidoOptionsStore>();
        
        services.AddScoped<IFidoAuthenticationService, FidoAuthenticationService>();
        services.AddScoped<FidoRegistrationService>();

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
}