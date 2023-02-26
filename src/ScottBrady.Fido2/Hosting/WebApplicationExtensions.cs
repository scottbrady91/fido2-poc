using System;
using Microsoft.AspNetCore.Builder;

namespace ScottBrady.Fido2;

public static class WebApplicationExtensions
{
    public static WebApplication UseWebAuthnApi(this WebApplication app)
    {
        // TODO: consider adding minimal API registrations for endpoints - how to get username?
        throw new NotImplementedException();
    }
}