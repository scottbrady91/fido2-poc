using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ScottBrady.Fido2;

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