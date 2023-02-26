using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using ScottBrady.Fido2.Models;

namespace ScottBrady.Fido2;

public class IntArrayConverter : JsonConverter<byte[]>
{
    public override byte[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        throw new NotImplementedException();
    }

    public override void Write(Utf8JsonWriter writer, byte[] value, JsonSerializerOptions options)
    {
        writer.WriteStartArray();
        foreach (var valueToWrite in value.Select(x => (uint)x))
        {
            writer.WriteNumberValue(valueToWrite);
        }
        writer.WriteEndArray();
    }
}

public class AuthenticatorResponseConverter : JsonConverter<AuthenticatorResponse>
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
            
            if (!jsonDocument.RootElement.TryGetProperty("signature", out _))
            {
                return JsonSerializer.Deserialize<AuthenticatorAttestationResponse>(jsonObject, options);
            }
            else
            {
                return JsonSerializer.Deserialize<AuthenticatorAssertionResponse>(jsonObject, options);
            }
        }
    }

    public override void Write(Utf8JsonWriter writer, AuthenticatorResponse value, JsonSerializerOptions options)
    {
        throw new NotImplementedException();
    }
}