using System.Text.Json;
using System.Text.Json.Serialization;

namespace ScottBrady.Fido2.Samples.Basic;

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