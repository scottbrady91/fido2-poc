using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
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
        app.MapPut("/fido/register", async (FidoRegistrationRequest request, FidoRegistrationService registrationService) =>
        {
            var options = await registrationService.Initiate(request);
            return Results.Json(options, new JsonSerializerOptions{Converters = { new IntArrayJsonConverter() }, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, PropertyNameCaseInsensitive = true}, statusCode: 200);
        });

        app.MapPost("/fido/register", async (PublicKeyCredential response, FidoRegistrationService registrationService) =>
        {
            var result = await registrationService.Complete(response);
            return Results.Json(result);
        });

        app.MapPut("/fido/authenticate", async (FidoAuthenticationRequest request, IFidoAuthenticationService authenticationService) =>
        {
            var options = await authenticationService.Initiate(request);
            return Results.Json(options, new JsonSerializerOptions{Converters = { new IntArrayJsonConverter() }, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, PropertyNameCaseInsensitive = true}, statusCode: 200);
        });

        app.MapPost("/fido/authenticate", async (PublicKeyCredential credential, IFidoAuthenticationService authenticationService) =>
        {
            var result = await authenticationService.Complete(credential);
            return Results.Json(result);
        });

        return app;
    }
}