using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
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
        var jsonSerializerOptions = new JsonSerializerOptions
        {
            Converters = { new IntArrayJsonConverter(), new EmptyToNullStringConverter() },
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
            PropertyNameCaseInsensitive = true
        };
        
        app.MapPut("/fido/register", async (HttpContext context, FidoRegistrationService registrationService) =>
        {
            var request = await JsonSerializer.DeserializeAsync<FidoRegistrationRequest>(context.Request.Body, jsonSerializerOptions);
            
            var options = await registrationService.Initiate(request);
            return Results.Json(options, jsonSerializerOptions, statusCode: 200);
        });

        app.MapPost("/fido/register", async (PublicKeyCredential response, FidoRegistrationService registrationService) =>
        {
            var result = await registrationService.Complete(response);
            if (result.IsSuccess) return Results.Json(result);
            return Results.BadRequest();
        });

        app.MapPut("/fido/authenticate", async (FidoAuthenticationRequest request, IFidoAuthenticationService authenticationService) =>
        {
            var options = await authenticationService.Initiate(request);
            return Results.Json(options, jsonSerializerOptions, statusCode: 200);
        });

        app.MapPost("/fido/authenticate", async (PublicKeyCredential credential, IFidoAuthenticationService authenticationService) =>
        {
            var result = await authenticationService.Complete(credential);
            if (result.IsSuccess) return Results.Json(result);
            return Results.BadRequest();
        });

        return app;
    }
}