using Microsoft.AspNetCore.Builder;
using ScottBrady.Fido2;


var builder = WebApplication.CreateBuilder(args);
builder.Services.AddWebAuthn(options =>
    {
        options.RelyingPartyId = "localhost";
        options.RelyingPartyName = "SB Test";
        options.RelyingPartyOrigin = "https://localhost:5000";
    })
    .AddInMemoryKeyStore();
var app = builder.Build();

app.MapGet("/", () => "Hello World!");
app.UseWebAuthnApi();

app.Run();