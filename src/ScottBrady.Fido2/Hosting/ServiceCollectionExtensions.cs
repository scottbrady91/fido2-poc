using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ScottBrady.Fido2.Stores;

namespace ScottBrady.Fido2;

/// <summary>
/// Extensions for registering FIDO dependencies.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the core dependencies for acting as a WebAuthn relying party.
    /// </summary>
    public static IServiceCollection AddWebAuthn(this IServiceCollection services, Action<FidoOptions> configureOptions)
    {
        services.Configure(configureOptions);

        services.AddScoped<FidoAuthenticationService>(
            (_) => new FidoAuthenticationService(new InMemoryFidoOptionsStore(), new InMemoryFidoKeyStore()));
        services.AddScoped<FidoRegistrationService>(
            (s) => new FidoRegistrationService(new InMemoryFidoOptionsStore(), s.GetRequiredService<IOptions<FidoOptions>>().Value));

        return services;
    }
}