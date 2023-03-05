using System;
using System.Collections.Generic;
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
    [InlineData(typeof(FidoRegistrationRequest))]
    [InlineData(typeof(FidoAuthenticationRequest))]
    [InlineData(typeof(PublicKeyCredentialCreationOptions))]
    [InlineData(typeof(PublicKeyCredentialRequestOptions))]
    [InlineData(typeof(PublicKeyCredentialRpEntity))]
    [InlineData(typeof(PublicKeyCredentialUserEntity))]
    [InlineData(typeof(PublicKeyCredentialParameters))]
    [InlineData(typeof(AuthenticatorSelectionCriteria))]
    [InlineData(typeof(PublicKeyCredentialDescriptor))]
    public void ExpectSerializableWithLowerCaseProperties(Type type)
    {
        var jsonOptions = new FidoOptions().JsonOptions;

        var fixture = new Fixture();
        var model = fixture.Create(type, new SpecimenContext(fixture));
        
        var json = JsonSerializer.Serialize(model, jsonOptions);
        IsLowerCamelCase(json).Should().BeTrue();
    }

    private static bool IsLowerCamelCase(string json)
    {
        var parsedJson = JsonNode.Parse(json);
        parsedJson.Should().NotBeNull();
        return IsLowerCamelCase(parsedJson);
    }

    private static bool IsLowerCamelCase(JsonNode json)
    {
        if (json is JsonObject)
        {
            foreach (KeyValuePair<string, JsonNode> element in json.AsObject())
            {
                if (Regex.IsMatch(element.Key[0].ToString(), "[A-Z]")) return false;
                if (!IsLowerCamelCase(element.Value)) return false;
            }
        }

        if (json is JsonArray)
        {
            foreach (JsonNode element in json.AsArray())
            {
                if (!IsLowerCamelCase(element)) return false;
            }
        }

        return true;
    }
}