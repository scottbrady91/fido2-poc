using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ScottBrady.Fido2;

public class IntArrayJsonConverter : JsonConverter<byte[]>
{
    public override byte[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.StartArray)
        {
            var bytes = new List<byte>();

            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.Number)
                {
                    bytes.Add(reader.GetByte());
                }
                
                if (reader.TokenType == JsonTokenType.EndArray) return bytes.ToArray();
            }
        }

        if (reader.TokenType == JsonTokenType.String)
        {
            var value = reader.GetString();
             return string.IsNullOrEmpty(value) ? Array.Empty<byte>() : Convert.FromBase64String(value);
        }
        
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