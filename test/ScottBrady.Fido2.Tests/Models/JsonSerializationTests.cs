using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AutoFixture;
using FluentAssertions;
using ScottBrady.Fido2.Models;
using Xunit;

namespace ScottBrady.Fido2.Tests.Models;

public class JsonSerializationTests
{
    [Fact]
    public void ExpectSerializable()
    {
        var model = new Fixture().Create<PublicKeyCredentialRequestOptions>();
        
        var json = JsonSerializer.Serialize(model);
        var parsedJson = JsonNode.Parse(json);
        parsedJson.Should().NotBeNull();
        foreach (var element in parsedJson.AsObject())
        {
            Regex.IsMatch(element.Key[0].ToString(), "[A-Z]").Should().BeFalse();
            if (element.Value is /*JsonObject or*/ JsonArray)
            {
                foreach (var arrayElement in element.Value.AsArray())
                {
                    arrayElement.AsObject().Any(x => Regex.IsMatch(x.Key[0].ToString(), "[A-Z]")).Should().BeFalse();
                }
            }
            
        }
        
        var parsedModel = JsonSerializer.Deserialize<PublicKeyCredentialRequestOptions>(json);
        parsedModel.Should().BeEquivalentTo(model);
    }
}