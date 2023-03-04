using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AutoFixture;
using AutoFixture.Kernel;
using FluentAssertions;
using ScottBrady.Fido2.Models;
using Xunit;

namespace ScottBrady.Fido2.Tests.Models;

public class JsonSerializationTests
{
    [Theory]
    [InlineData(typeof(PublicKeyCredentialRequestOptions))]
    public void ExpectSerializable(Type type)
    {
        var fixture = new Fixture();
        var model = fixture.Create(type, new SpecimenContext(fixture));
        
        var json = JsonSerializer.Serialize(model);
        IsLowerCamelCase(json).Should().BeTrue();
        
        var parsedModel = JsonSerializer.Deserialize<PublicKeyCredentialRequestOptions>(json);
        parsedModel.Should().BeEquivalentTo(model);
    }

    private bool IsLowerCamelCase(string json)
    {
        var parsedJson = JsonNode.Parse(json);
        parsedJson.Should().NotBeNull();
        return IsLowerCamelCase(parsedJson);
    }

    private bool IsLowerCamelCase(JsonNode json)
    {
        foreach (var element in json.AsObject())
        {
            if (Regex.IsMatch(element.Key[0].ToString(), "[A-Z]")) return false;
            
            if (element.Value is /*JsonObject or*/ JsonArray)
            {
                foreach (var arrayElement in element.Value.AsArray())
                {
                    if (arrayElement.AsObject().Any(x => Regex.IsMatch(x.Key[0].ToString(), "[A-Z]"))) return false;
                }
            }
        }

        return true;
    }
}