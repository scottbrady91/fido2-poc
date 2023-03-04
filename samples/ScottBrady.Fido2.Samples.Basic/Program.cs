using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using ScottBrady.Fido2;
using ScottBrady.Fido2.Stores;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddWebAuthn(options => options.RelyingPartyName = "SB Test")
    .AddInMemoryKeyStore();

var app = builder.Build();

app.UseDeveloperExceptionPage();

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseWebAuthnApi();

app.MapGet("/fido/keys", () => Results.Json(InMemoryFidoKeyStore.Keys));

app.Run();