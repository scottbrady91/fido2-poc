using System.Text.Json;
using ScottBrady.Fido2;
using ScottBrady.Fido2.Models;
using ScottBrady.Fido2.Samples.Basic;
using ScottBrady.Fido2.Stores;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.UseDeveloperExceptionPage();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/fido/register", async () =>
{
    var options = await new FidoRegistrationService(new InMemoryFidoOptionsStore()).Initiate(new FidoRegistrationRequest("Scott", "Scott - test (minimal API)"));
    
    return Results.Json(options, new JsonSerializerOptions{Converters = { new IntArrayConverter() }, PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase}, statusCode: 200);
});

app.MapPost("/fido/register", async (PublicKeyCredential response) =>
{
    await new FidoRegistrationService(new InMemoryFidoOptionsStore()).Complete(response.Response.ClientDataJson, response.Response.AttestationObject);
});

app.Run();