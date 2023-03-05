using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using ScottBrady.Fido2;
using ScottBrady.Fido2.Stores;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddWebAuthn(options =>
    {
        options.RelyingPartyId = "localhost";
        options.RelyingPartyName = "SB Test";
        options.RelyingPartyOrigin = "https://localhost:5000";
    })
    .AddJsonFileKeyStore();

var app = builder.Build();

app.UseDeveloperExceptionPage();

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseWebAuthnApi();

// demo endpoint to view current key store
app.MapGet("/fido/keys", (JsonFidoKeyStore store) => 
        Results.Json(store.Keys, new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));

app.Run();