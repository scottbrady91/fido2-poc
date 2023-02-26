using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using ScottBrady.Fido2;
using ScottBrady.Fido2.Models;
using ScottBrady.Fido2.Stores;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddWebAuthn(options => options.RelyingPartyName = "SB Test");

var app = builder.Build();

app.UseDeveloperExceptionPage();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/fido/register", async (FidoRegistrationService registrationService) =>
{
    var options = await registrationService.Initiate(new FidoRegistrationRequest("Scott", "Scott - test (minimal API)"));
    return Results.Json(options, new JsonSerializerOptions{Converters = { new IntArrayJsonConverter() }, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, PropertyNameCaseInsensitive = true}, statusCode: 200);
});

app.MapPost("/fido/register", async (PublicKeyCredential response, FidoRegistrationService registrationService) =>
{
    var result = await new FidoRegistrationService(new InMemoryFidoOptionsStore(), new FidoOptions()).Complete(response);
    return Results.Json(result);
});

app.MapGet("/fido/authenticate", async (FidoAuthenticationService authenticationService) =>
{
    var options = await authenticationService.Initiate(new FidoAuthenticationRequest("Scott"));
    return Results.Json(options, new JsonSerializerOptions{Converters = { new IntArrayJsonConverter() }, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, PropertyNameCaseInsensitive = true}, statusCode: 200);
});

app.MapPost("/fido/authenticate", async (PublicKeyCredential credential, FidoAuthenticationService authenticationService) =>
{
    var result = await authenticationService.Complete(credential);
    return Results.Json(result);
});

app.Run();