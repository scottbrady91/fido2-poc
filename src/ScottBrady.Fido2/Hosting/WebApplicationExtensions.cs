using System;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ScottBrady.Fido2.Models;

namespace ScottBrady.Fido2;

/// <summary>
/// Extensions for registering API endpoints.
/// </summary>
public static class WebApplicationExtensions
{
    /// <summary>
    /// Registers the API endpoints to act as a WebAuthn relying party.
    /// </summary>
    public static WebApplication UseWebAuthnApi(this WebApplication app)
    {
        app.MapPut("/fido/register", async (HttpContext context, ILogger<FidoRegistrationService> logger, FidoRegistrationService registrationService, IOptions<FidoOptions> configurationOptions) =>
        {
            try
            {
                var request = await JsonSerializer.DeserializeAsync<FidoRegistrationRequest>(context.Request.Body, configurationOptions.Value.JsonSerializerOptions);
                var options = await registrationService.Initiate(request);
                return Results.Json(options, configurationOptions.Value.JsonSerializerOptions, statusCode: 200);
            }
            catch (Exception e)
            {
                logger.LogError(e, "Failed to generate FIDO registration options");
                return Results.BadRequest();
            }
        });

        app.MapPost("/fido/register", async (HttpContext context, ILogger<FidoRegistrationService> logger, FidoRegistrationService registrationService, IOptions<FidoOptions> configurationOptions) =>
        {
            try
            {
                var credential = await JsonSerializer.DeserializeAsync<PublicKeyCredential>(context.Request.Body, configurationOptions.Value.JsonSerializerOptions);
                var result = await registrationService.Complete(credential);
                return result.IsSuccess ? Results.Json(result) : Results.BadRequest();
            }
            catch (Exception e)
            {
                logger.LogError(e, "Failed to register FIDO credentials");
                return Results.BadRequest();
            }
        });

        app.MapPut("/fido/authenticate", async (HttpContext context, ILogger<FidoRegistrationService> logger, IFidoAuthenticationService authenticationService, IOptions<FidoOptions> configurationOptions) =>
        {
            try
            {
                var request = await JsonSerializer.DeserializeAsync<FidoAuthenticationRequest>(context.Request.Body, configurationOptions.Value.JsonSerializerOptions);
                var options = await authenticationService.Initiate(request);
                return Results.Json(options, configurationOptions.Value.JsonSerializerOptions, statusCode: 200);
            }
            catch (Exception e)
            {
                logger.LogError(e, "Failed to generate FIDO authentication options");
                return Results.BadRequest();
            }
        });

        app.MapPost("/fido/authenticate", async (HttpContext context, ILogger<FidoRegistrationService> logger, IFidoAuthenticationService authenticationService, IOptions<FidoOptions> configurationOptions) =>
        {
            try
            {
                var credential = await JsonSerializer.DeserializeAsync<PublicKeyCredential>(context.Request.Body, configurationOptions.Value.JsonSerializerOptions);
                var result = await authenticationService.Complete(credential);
                return result.IsSuccess ? Results.Json(result) : Results.BadRequest();
            }
            catch (Exception e)
            {
                logger.LogError(e, "Failed to authenticate FIDO credentials");
                return Results.BadRequest();
            }
        });

        return app;
    }
}