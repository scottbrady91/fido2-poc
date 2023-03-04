using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ScottBrady.Fido2;

public class IntArrayJsonConverter : JsonConverter<byte[]>
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

public class EmptyToNullStringConverter : JsonConverter<string>
{
    public override string Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        return !string.IsNullOrWhiteSpace(value) ? value : null;
    }

    public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value);
    }
}