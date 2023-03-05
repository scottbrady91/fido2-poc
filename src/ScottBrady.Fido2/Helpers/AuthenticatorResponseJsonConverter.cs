using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using ScottBrady.Fido2.Models;

namespace ScottBrady.Fido2;

public class AuthenticatorResponseJsonConverter : JsonConverter<AuthenticatorResponse>
{
    public override AuthenticatorResponse Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException();
        }

        using (var jsonDocument = JsonDocument.ParseValue(ref reader))
        {
            var jsonObject = jsonDocument.RootElement.GetRawText();
            
            // TODO: check value not null too
            if (!jsonDocument.RootElement.TryGetProperty("signature", out _))
            {
                return JsonSerializer.Deserialize<AuthenticatorAttestationResponse>(jsonObject, options);
            }

            return JsonSerializer.Deserialize<AuthenticatorAssertionResponse>(jsonObject, options);
        }
    }

    public override void Write(Utf8JsonWriter writer, AuthenticatorResponse value, JsonSerializerOptions options)
    {
        if (value is AuthenticatorAttestationResponse attestationResponse)
        {
            JsonSerializer.Serialize(writer, attestationResponse, options);
        }
        else if (value is AuthenticatorAssertionResponse assertionResponse)
        {
            JsonSerializer.Serialize(writer, assertionResponse, options);
        }
        else
        {
            throw new NotImplementedException();
        }
    }
}