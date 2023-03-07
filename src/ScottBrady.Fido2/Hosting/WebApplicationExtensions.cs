using System;
using System.Text.Json;
using System.Threading.Tasks;
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
        app.MapPut("/fido/register", (HttpContext context, ILogger<IFidoRegistrationService> logger, IFidoRegistrationService registrationService, IOptions<FidoOptions> configurationOptions)
            => WebAuthnMinimalApiHandlers.InitiateRegistration(context, logger, registrationService, configurationOptions));

        app.MapPost("/fido/register", (HttpContext context, ILogger<IFidoRegistrationService> logger, IFidoRegistrationService registrationService, IOptions<FidoOptions> configurationOptions)
            => WebAuthnMinimalApiHandlers.CompleteRegistration(context, logger, registrationService, configurationOptions));

        app.MapPut("/fido/authenticate", (HttpContext context, ILogger<IFidoAuthenticationService> logger, IFidoAuthenticationService authenticationService, IOptions<FidoOptions> configurationOptions) 
            => WebAuthnMinimalApiHandlers.InitiateAuthentication(context, logger, authenticationService, configurationOptions));

        app.MapPost("/fido/authenticate", (HttpContext context, ILogger<IFidoAuthenticationService> logger, IFidoAuthenticationService authenticationService, IOptions<FidoOptions> configurationOptions)
            => WebAuthnMinimalApiHandlers.CompleteAuthentication(context, logger, authenticationService, configurationOptions));

        return app;
    }

    private static class WebAuthnMinimalApiHandlers
    {
        public static async Task<IResult> InitiateRegistration(
            HttpContext context,
            ILogger logger,
            IFidoRegistrationService registrationService,
            IOptions<FidoOptions> configurationOptions)
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
        }

        public static async Task<IResult> CompleteRegistration(
            HttpContext context,
            ILogger logger,
            IFidoRegistrationService registrationService,
            IOptions<FidoOptions> configurationOptions)
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
        }
        public static async Task<IResult> InitiateAuthentication(
            HttpContext context,
            ILogger logger,
            IFidoAuthenticationService authenticationService,
            IOptions<FidoOptions> configurationOptions)
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
        }

        public static async Task<IResult> CompleteAuthentication(
            HttpContext context,
            ILogger logger,
            IFidoAuthenticationService authenticationService,
            IOptions<FidoOptions> configurationOptions)
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
        }
    }
}