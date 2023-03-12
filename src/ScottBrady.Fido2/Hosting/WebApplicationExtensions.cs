using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
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
        app.MapPut("/fido/register", WebAuthnMinimalApiHandlers.InitiateRegistration);

        app.MapPost("/fido/register", (HttpContext context, ILogger<IFidoRegistrationService> logger, IFidoRegistrationService registrationService, IOptions<FidoOptions> configurationOptions)
            => WebAuthnMinimalApiHandlers.CompleteRegistration(context, logger, registrationService, configurationOptions));

        app.MapPut("/fido/authenticate", (HttpContext context, ILogger<IFidoAuthenticationService> logger, IFidoAuthenticationService authenticationService, IOptions<FidoOptions> configurationOptions) 
            => WebAuthnMinimalApiHandlers.InitiateAuthentication(context, logger, authenticationService, configurationOptions));

        app.MapPost("/fido/authenticate", (HttpContext context, ILogger<IFidoAuthenticationService> logger, IFidoAuthenticationService authenticationService, IOptions<FidoOptions> configurationOptions)
            => WebAuthnMinimalApiHandlers.CompleteAuthentication(context, logger, authenticationService, configurationOptions));

        return app;
    }

    /// <summary>
    /// Registers the API endpoints to act as a WebAuthn relying party with support for FIDO's conformance testing tool.
    /// </summary>
    /// <remarks>
    /// Implements the <a href="https://github.com/fido-alliance/conformance-test-tools-resources/blob/master/docs/FIDO2/Server/Conformance-Test-API.md">FIDO2 Conformance testing server API</a>.
    /// </remarks>
    public static WebApplication UseFidoConformanceApi(this WebApplication app)
    {
        app.MapPost("/attestation/options", async (HttpContext context, ILogger<IFidoRegistrationService> logger, IFidoRegistrationService registrationService, IOptions<FidoOptions> configurationOptions) =>
        {
            try
            {
                var request = await JsonSerializer.DeserializeAsync<FidoRegistrationRequest>(context.Request.Body, configurationOptions.Value.JsonSerializerOptions);
                var options = await registrationService.Initiate(request);
                return Results.Json(new ServerPublicKeyCredentialCreationOptionsResponse(options), configurationOptions.Value.JsonSerializerOptions);
            }
            catch (FidoException e)
            {
                return Results.BadRequest(ServerResponse.Failure(e));
            }
        });
        
        // https://github.com/fido-alliance/conformance-test-tools-resources/blob/master/docs/FIDO2/Server/Conformance-Test-API.md#example-authenticator-attestation-response
        app.MapPost("/attestation/result", async (HttpContext context, ILogger<IFidoRegistrationService> logger, IFidoRegistrationService registrationService, IOptions<FidoOptions> configurationOptions) =>
        {
            try
            {
                var credential = await JsonSerializer.DeserializeAsync<ServerPublicKeyCredential>(context.Request.Body, configurationOptions.Value.JsonSerializerOptions);
                var result = await registrationService.Complete(credential.ToWebAuthn());
                return result.IsSuccess ? Results.Json(ServerResponse.Success()) : Results.BadRequest(ServerResponse.Failure(result));
            }
            catch (FidoException e)
            {
                return Results.BadRequest(ServerResponse.Failure(e));
            }
        });
        
        return app;
    }

    internal class ServerResponse
    {
        public static ServerResponse Success() => new ServerResponse { status = "ok", errorMessage = "" };
        public static ServerResponse Failure(FidoRegistrationResult result) => new ServerResponse { status = "failed", errorMessage = result.Error };
        public static ServerResponse Failure(Exception exception) => new ServerResponse { status = "failed", errorMessage = exception.Message };
        
        public string status { get; private init; } = "ok"; // 👍
        public string errorMessage { get; private init; } = ""; // required 🤣
    }

    // https://github.com/fido-alliance/conformance-test-tools-resources/blob/master/docs/FIDO2/Server/Conformance-Test-API.md#serverpublickeycredentialcreationoptionsresponse
    internal class ServerPublicKeyCredentialCreationOptionsResponse : ServerResponse
    {
        public ServerPublicKeyCredentialCreationOptionsResponse(PublicKeyCredentialCreationOptions options)
        {
            rp = options.RelyingParty;
            user = new ServerPublicKeyCredentialUserEntity(options.User);
            challenge = Base64UrlTextEncoder.Encode(options.Challenge);
            pubKeyCredParams = options.PublicKeyCredentialParameters;
            timeout = options.Timeout;
            excludeCredentials = options.ExcludeCredentials.Select(x => new ServerPublicKeyCredentialDescriptor(x)).ToList();
            authenticatorSelection = options.AuthenticatorSelectionCriteria;
            attestation = options.Attestation;
            extensions = options.Extensions;
        }

        public PublicKeyCredentialRpEntity rp { get; }
        public ServerPublicKeyCredentialUserEntity user { get; }
        public string challenge { get; }
        public IEnumerable<PublicKeyCredentialParameters> pubKeyCredParams { get; }
        public int? timeout { get; }
        public IEnumerable<ServerPublicKeyCredentialDescriptor> excludeCredentials { get; }
        public AuthenticatorSelectionCriteria authenticatorSelection { get; }
        public string attestation { get; }
        public Dictionary<string, object> extensions { get; }
    }

    // https://github.com/fido-alliance/conformance-test-tools-resources/blob/master/docs/FIDO2/Server/Conformance-Test-API.md#serverpublickeycredential
    internal class ServerPublicKeyCredential
    {
        public string id { get; set; }
        public string type { get; set; }
        public ServerAuthenticatorAttestationResponse response { get; set; }
        public object getClientExtensionResults { get; set; } // TODO: getClientExtensionResults

        public PublicKeyCredential ToWebAuthn() =>
            new PublicKeyCredential
            {
                Id = id,
                RawId = Base64UrlTextEncoder.Decode(id),
                Type = type,
                Response = new AuthenticatorAttestationResponse
                {
                    ClientDataJson = Base64UrlTextEncoder.Decode(response.clientDataJSON),
                    AttestationObject = Base64UrlTextEncoder.Decode(response.attestationObject)
                }
            };
    }

    // https://github.com/fido-alliance/conformance-test-tools-resources/blob/master/docs/FIDO2/Server/Conformance-Test-API.md#serverauthenticatorattestationresponse
    internal class ServerAuthenticatorAttestationResponse // TODO: unknown base type in Github (ServerAuthenticatorResponse) 
    {
        public string clientDataJSON { get; set; }
        public string attestationObject { get; set; }
    }

    internal class ServerPublicKeyCredentialUserEntity
    {
        public ServerPublicKeyCredentialUserEntity(PublicKeyCredentialUserEntity user)
        {
            id = Base64UrlTextEncoder.Encode(user.Id);
            name = user.Name;
            displayName = user.DisplayName;
        }
        
        public string id { get; }
        public string name { get; }
        public string displayName { get; }
    }

    internal class ServerPublicKeyCredentialDescriptor
    {
        public ServerPublicKeyCredentialDescriptor(PublicKeyCredentialDescriptor descriptor)
        {
            id = Base64UrlTextEncoder.Encode(descriptor.Id);
            type = descriptor.Type;
            transports = descriptor.Transports;
        }
        
        public string id { get; }
        public string type { get; }
        public IEnumerable<string> transports { get; }
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